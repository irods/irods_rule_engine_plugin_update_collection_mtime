#include "irods_plugin_context.hpp"
#include "irods_re_plugin.hpp"
#include "irods_re_serialization.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_get_l1desc.hpp"
#include "irods_at_scope_exit.hpp"
#include "objInfo.h"
#include "dataObjInpOut.h"
#include "rcMisc.h"
#include "rsModColl.hpp"

#include <string>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>

#include <boost/filesystem.hpp>

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

namespace {

constexpr int timestamp_buffer_size = 15;

// This is a "sorted" list of the supported PEPs.
// This will allow us to do binary search on the list for lookups.
const std::array<std::string, 7> peps{{
    "pep_api_coll_create_post",
    "pep_api_data_obj_close_post",
    "pep_api_data_obj_close_pre",
    "pep_api_data_obj_put_post",
    "pep_api_data_obj_rename_post",
    "pep_api_data_obj_unlink_post",
    "pep_api_rm_coll_post"
}};

namespace util {

ruleExecInfo_t& get_rei(irods::callback& _effect_handler)
{
    ruleExecInfo_t* rei{};
    irods::error result{_effect_handler("unsafe_ms_ctx", &rei)};

    if (!result.ok()) {
        THROW(result.code(), "failed to get rule execution info");
    }

    return *rei;
}

template <typename Function>
auto sudo(ruleExecInfo_t& _rei, Function _func) -> decltype(_func())
{
    auto& auth_flag = _rei.rsComm->clientUser.authInfo.authFlag;
    const auto old_auth_flag = auth_flag;

    // Elevate privileges.
    auth_flag = LOCAL_PRIV_USER_AUTH;

    // Restore authorization flags on exit.
    irods::at_scope_exit<std::function<void()>> at_scope_exit{
        [&auth_flag, old_auth_flag] { auth_flag = old_auth_flag; }
    };

    return _func();
}

void update_collection_mtime(irods::callback& _effect_handler,
                             const std::string& _path,
                             const char* _new_mtime = nullptr)
{
    rodsLog(LOG_DEBUG, "updating collection mtime for [%s] ...", _path.c_str());

    collInp_t input{};

    if (!rstrcpy(input.collName, _path.c_str(), MAX_NAME_LEN)) {
        rodsLog(LOG_ERROR, "failed to copy path into update arguments [path => %s]", _path.c_str());
        return;
    }

    if (_new_mtime) {
        addKeyVal(&input.condInput, COLLECTION_MTIME_KW, _new_mtime);
    }
    else {
        char now[timestamp_buffer_size];
        getNowStr(now);
        addKeyVal(&input.condInput, COLLECTION_MTIME_KW, now);
    }

    auto& rei = get_rei(_effect_handler);

    const auto ec = sudo(rei, [&rei, &input] {
        return rsModColl(rei.rsComm, &input);
    });

    if (ec != 0) {
        rodsLog(LOG_ERROR, "failed to update collection mtime for [%s] [error code => %d]", _path.c_str(), ec);
    }
}

std::string parent_path(const char* _path)
{
    namespace fs = boost::filesystem;
    return fs::path{_path}.parent_path().generic_string();
}

std::string to_string(const collInp_t& _input)
{
    std::string output = "collInp_t {collName: ";
    output += _input.collName;
    output += '}';

    return output;
}

std::string to_string(const openedDataObjInp_t& _input)
{
    std::string output = "openedDataObjInp_t {";
    output += "l1descInx: ";
    output += std::to_string(_input.l1descInx);
    output += ", len: ";
    output += std::to_string(_input.len);
    output += ", oprType: ";
    output += std::to_string(_input.oprType);
    output += ", bytesWritten: ";
    output += std::to_string(_input.bytesWritten);
    output += '}';

    return output;
}

std::string to_string(const dataObjInp_t& _input)
{
    std::string output = "dataObjInp_t {objPath: ";
    output += _input.objPath;
    output += '}';

    return output;
}

std::string to_string(const dataObjCopyInp_t& _input)
{
    std::string output = "dataObjCopyInp_t {";
    output += "srcDataObjInp.objPath: ";
    output += _input.srcDataObjInp.objPath;
    output += ", destDataObjInp.objPath: ";
    output += _input.destDataObjInp.objPath;
    output += '}';

    return output;
}

std::string to_string(const l1desc& _input)
{
    std::string output = "l1desc {";
    output += "dataObjInp->objPath: ";
    output += _input.dataObjInp->objPath;
    output += ", bytesWritten: ";
    output += std::to_string(_input.bytesWritten);
    output += '}';

    return output;
}

} // namespace util

//
// PEP Handlers
//

namespace handler {

irods::error pep_api_coll_create_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
{
    rodsLog(LOG_DEBUG, ">>> pep_api_coll_create_post");

    try
    {
        auto iter = std::begin(_rule_arguments);
        auto* input = boost::any_cast<collInp_t*>(*std::next(iter, 2));

        rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

        util::update_collection_mtime(_effect_handler, util::parent_path(input->collName));
    }
    catch (const std::exception& e)
    {
        rodsLog(LOG_ERROR, "%s", e.what());
    }
    
    return SUCCESS();
}

class pep_api_data_obj_close
{
public:
    pep_api_data_obj_close() = delete;

    static irods::error pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
    {
        rodsLog(LOG_DEBUG, ">>> pep_api_data_obj_close_pre");

        try
        {
            auto iter = std::begin(_rule_arguments);
            auto* input = boost::any_cast<openedDataObjInp_t*>(*std::next(iter, 2));

            rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

            const auto& desc = irods::get_l1desc(input->l1descInx);

            rodsLog(LOG_DEBUG, util::to_string(desc).c_str());

            logical_path_ = desc.dataObjInp->objPath;
        }
        catch (const std::exception& e)
        {
            rodsLog(LOG_ERROR, "%s", e.what());
        }
        
        return SUCCESS();
    }

    static irods::error post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
    {
        rodsLog(LOG_DEBUG, ">>> pep_api_data_obj_close_post");

        static constexpr std::array<int, 11> unsupported_operations{{
            DONE_OPR,
            GET_OPR,
            REPLICATE_SRC,
            COPY_SRC,
            PHYMV_SRC,
            QUERY_DATA_OBJ,
            QUERY_DATA_OBJ_RECUR,
            QUERY_COLL_OBJ,
            QUERY_COLL_OBJ_RECUR,
            RENAME_UNKNOWN_TYPE,
            REMOTE_ZONE_OPR
        }};

        try
        {
            auto iter = std::begin(_rule_arguments);
            auto* input = boost::any_cast<openedDataObjInp_t*>(*std::next(iter, 2));

            rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

            auto b = std::cbegin(unsupported_operations);
            auto e = std::cend(unsupported_operations);

            if (std::none_of(b, e, [op = input->oprType](const auto& _op) { return _op == op; })) {
                util::update_collection_mtime(_effect_handler, util::parent_path(logical_path_.c_str()));
            }
        }
        catch (const std::exception& e)
        {
            rodsLog(LOG_ERROR, "%s", e.what());
        }
        
        return SUCCESS();
    }

private:
    static std::string logical_path_;
}; // pep_api_data_obj_close

std::string pep_api_data_obj_close::logical_path_{};

irods::error pep_api_data_obj_put_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
{
    rodsLog(LOG_DEBUG, ">>> pep_api_data_obj_put_post");

    try
    {
        auto iter = std::begin(_rule_arguments);
        auto* input = boost::any_cast<dataObjInp_t*>(*std::next(iter, 2));

        rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

        util::update_collection_mtime(_effect_handler, util::parent_path(input->objPath));
    }
    catch (const std::exception& e)
    {
        rodsLog(LOG_ERROR, "%s", e.what());
    }

    return SUCCESS();
}

irods::error pep_api_data_obj_rename_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
{
    rodsLog(LOG_DEBUG, ">>> pep_api_data_obj_rename_post");

    try
    {
        auto iter = std::begin(_rule_arguments);
        auto* input = boost::any_cast<dataObjCopyInp_t*>(*std::next(iter, 2));

        rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

        char now[timestamp_buffer_size];
        getNowStr(now);

        util::update_collection_mtime(_effect_handler, util::parent_path(input->srcDataObjInp.objPath), now);

        // If the source collection does not match the destination collection, this means a second collection
        // is involved in the rename and will need it's mtime updated as well (e.g. imv col/dobj other_col/dobj).
        if (std::string{input->srcDataObjInp.objPath} != input->destDataObjInp.objPath) {
            util::update_collection_mtime(_effect_handler, util::parent_path(input->destDataObjInp.objPath), now);
        }
    }
    catch (const std::exception& e)
    {
        rodsLog(LOG_ERROR, "%s", e.what());
    }

    return SUCCESS();
}

irods::error pep_api_data_obj_unlink_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
{
    rodsLog(LOG_DEBUG, ">>> pep_api_data_obj_unlink_post");

    try
    {
        auto iter = std::begin(_rule_arguments);
        auto* input = boost::any_cast<dataObjInp_t*>(*std::next(iter, 2));

        rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

        util::update_collection_mtime(_effect_handler, util::parent_path(input->objPath));
    }
    catch (const std::exception& e)
    {
        rodsLog(LOG_ERROR, "%s", e.what());
    }

    return SUCCESS();
}

irods::error pep_api_rm_coll_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
{
    rodsLog(LOG_DEBUG, ">>> pep_api_rm_coll_post");

    try
    {
        auto iter = std::begin(_rule_arguments);
        auto* input = boost::any_cast<collInp_t*>(*std::next(iter, 2));

        rodsLog(LOG_DEBUG, util::to_string(*input).c_str());

        util::update_collection_mtime(_effect_handler, util::parent_path(input->collName));
    }
    catch (const std::exception& e)
    {
        rodsLog(LOG_ERROR, "%s", e.what());
    }

    return SUCCESS();
}

} // namespace handler

//
// Rule Engine Plugin
//

template <typename ...Args>
using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

irods::error rule_exists(irods::default_re_ctx&, const std::string& _rule_name, bool& _exists)
{
    _exists = std::binary_search(std::begin(peps), std::end(peps), _rule_name);
    return SUCCESS();
}

irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules)
{
    _rules.insert(std::end(_rules), std::begin(peps), std::end(peps));
    return SUCCESS();
}

irods::error exec_rule(irods::default_re_ctx&,
                       const std::string& _rule_name,
                       std::list<boost::any>& _rule_arguments,
                       irods::callback _effect_handler)
{
    using handler_t = std::function<irods::error(std::list<boost::any>&, irods::callback&)>;

    static const std::map<std::string, handler_t> handlers{
        {peps[0], handler::pep_api_coll_create_post},
        {peps[1], handler::pep_api_data_obj_close::post},
        {peps[2], handler::pep_api_data_obj_close::pre},
        {peps[3], handler::pep_api_data_obj_put_post},
        {peps[4], handler::pep_api_data_obj_rename_post},
        {peps[5], handler::pep_api_data_obj_unlink_post},
        {peps[6], handler::pep_api_rm_coll_post}
    };

    auto iter = handlers.find(_rule_name);

    if (std::end(handlers) != iter) {
        return (iter->second)(_rule_arguments, _effect_handler);
    }

    rodsLog(LOG_ERROR,
            "[irods_rule_engine_plugin-update_collection_mtime][rule => %s] "
            "rule not supported in rule engine plugin",
            _rule_name.c_str());

    return SUCCESS();
}

} // namespace (anonymous)

//
// Plugin Factory
//

extern "C"
pluggable_rule_engine* plugin_factory(const std::string& _instance_name,
                                      const std::string& _context)
{
    // clang-format off
    const auto no_op         = [] { return SUCCESS(); };
    const auto not_supported = [] { return ERROR(SYS_NOT_SUPPORTED, "Not supported"); };
    // clang-format on

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", {no_op});
    re->add_operation("stop", {no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", {not_supported});
    re->add_operation("exec_rule_expression", {not_supported});

    return re;
}

