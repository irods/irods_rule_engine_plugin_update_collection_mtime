# iRODS Rule Engine Plugin - Update Collection MTime

This plugin was developed as a dependency for [NFSRODS](https://github.com/irods/irods_client_nfsrods).

This plugin brings iRODS closer to POSIX semantics by enabling iRODS to automatically update the mtimes for
collections when changes are detected within them.

## Requirements
The following packages must be for iRODS v4.2.5:
- irods-externals packages
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
You should now have a `deb` package with a name similar to the following:
```bash
irods-rule-engine-plugin-update-collection-mtime-<plugin_version>-<os>-<arch>.deb
```

## Installing
```bash
$ sudo dpkg -i irods-rule-engine-plugin-update-collection-mtime-<plugin_version>-<os>-<arch>.deb
```
If the installation worked, you should now have a new shared library located under `<irods_lib_home>/plugins/rule_engines`.
The name of the new shared library should be `libirods_rule_engine_plugin-update_collection_mtime.so`.

## Configuration
To enable, prepend the following plugin config to the list of rule engines in `/etc/irods/server_config.json`:
```javascript
"plugin_configuration": {
    ...

    "rule_engines": [
        {
            "instance_name": "irods_rule_engine_plugin-update_collection_mtime-instance",
            "plugin_name": "irods_rule_engine_plugin-update_collection_mtime",
            "plugin_specific_configuration": {}
        },

    ...
```

