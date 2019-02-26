# iRODS Rule Engine Plugin - Update Collection MTime

This plugin was developed as a dependency for [NFSRODS](https://github.com/irods/irods_client_nfsrods).

This plugin brings iRODS closer to POSIX semantics by enabling iRODS to automatically update the mtimes for
collections when changes are detected within them.

## Requirements
- iRODS v4.2.5+
- irods-externals-boost package
- irods-dev package
- irods-runtime package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_update_collection_mtime
$ mkdir _build
$ cd _build
$ cmake -GNinja ../irods_rule_engine_plugin_update_collection_mtime
$ ninja package
```
After compiling, you should now have a `deb` or `rpm` package with a name similar to the following:
```bash
irods-rule-engine-plugin-update-collection-mtime-<plugin_version>-<os>-<arch>.<deb|rpm>
```

## Installing
Ubuntu:
```bash
$ sudo dpkg -i irods-rule-engine-plugin-update-collection-mtime-*.deb
```
CentOS:
```bash
$ su -c yum localinstall irods-rule-engine-plugin-update-collection-mtime-*.rpm
```
If the installation was successful, you should now have a new shared library. The full path to the library
should be similar to the following:
```
<irods_lib_home>/plugins/rule_engines/libirods_rule_engine_plugin-update_collection_mtime.so
```

## Configuration
To enable, prepend the following plugin config to the list of rule engines in `/etc/irods/server_config.json`. 
The plugin config must be placed at the beginning of the `"rule_engines"` section. Placing the plugin after other 
plugins could result in mtimes not being updated.

Even though this plugin will process PEPs first due to it's positioning, subsequent Rule Engine Plugins (REP) will 
still be allowed to process the same PEPs without any issues.
```javascript
"rule_engines": [
    {
        "instance_name": "irods_rule_engine_plugin-update_collection_mtime-instance",
        "plugin_name": "irods_rule_engine_plugin-update_collection_mtime",
        "plugin_specific_configuration": {}
    },
    
    // ... Previously installed rule engine plugin configs ...
]
```

Because iRODS v4.2.5+ allows multiple REPs to process the same PEPs, it is likely that errors will appear in the
log file and on the client-side. These errors occur because the PEPs that trigger continuation in the Rule Engine
Plugin Framework aren't properly handled by a later REP.

To fix this, two rulebase templates are provided:
- `/etc/irods/update_collection_mtime.re.template` - For users of the Native REP
- `/etc/irods/update_collection_mtime.py.template` - For users of the Python REP

### How to use the Templates
#### Native Rule Engine Plugin
If you are using the Native REP, do the following:
1. Copy `update_collection_mtime.re.template` and remove the **.template** extension.
2. Add a new entry to the `re_rulebase_set` list of the Native REP as shown below.
```javascript
"rule_engines": [
    // ... Previously installed rule engine plugin configs (including the MTime REP) ...

    {
        "instance_name": "irods_rule_engine_plugin-irods_rule_language-instance",
        "plugin_name": "irods_rule_engine_plugin-irods_rule_language",
        "plugin_specific_configuration": {
            "re_rulebase_set": [
                "core",
                "update_collection_mtime"
            ]
        }
    }
]
```

#### Python Rule Engine Plugin
Append the contents of `update_collection_mtime.py.template` to `/etc/irods/core.py`.
