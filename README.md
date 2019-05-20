# hsm-keymanager

Implements both signing and key storage logic for the server's signing operations. 
This is a hsm-based `KeyManager` plugin.
This implementation uses software emulation of HSM - [SoftHSM](https://www.opendnssec.org/softhsm/).

Plugin has specific options, which are used for configuration: 

| Options	| Description |
| --- | ---|
|`hsm_path`|The path to SoftHSM library|
|`token_label`|The name of the user token|
|`user_pin`|The PIN for the user token|

For installation [SoftHSM](https://www.opendnssec.org/softhsm/) use following instruction:
```
link-to-install-guide
```

## Initialize SohtHSM token

Initialize new token if it is necessary:

```
$ softhsm2-util --init-token --slot <slot_number> --label <token_name> --pin <User_PIN> --so-pin <SO_PIN>
```

The following table describes the token options: 

| Options	| Description |
| --- | ---|
|`--slot`|The slot where the token is located|
|`--label`|Defines the label of the token|
|`--pin`|The PIN for the normal user|
|`--so-pin`|The PIN for the Security Officer (SO)|

For example: 

```
$ softhsm2-util --init-token --slot 0 --label "hsm_test" --pin "userpin" --so-pin "sopin"
```

## Compiling the Plugin

    $ git clone https://github.com/seemenkina/hsm-keymanager
    $ cd hsm-keymanager/
    $ go build .

## Configure SPIRE

SPIRE Server during bootstrap, read plugin config files in the `/opt/spire/conf/server/plugin directories` by default, pluginDir configuration can be changed in `/opt/spire/conf/server/server.conf`.

1. Create a config file `hsm-keymanager.hcl` with the following content in the `/opt/spire/conf/server/plugin` directory:
 
````  
plugin_name = "hsmkeymanager"
plugin_cmd = "/path/to/plugin_binary"
plugin_checksum = ""
enabled = true
plugin_type = "KeyManager"
plugin_data {
    hsm_path = "/usr/lib/softhsm/libsofthsm2.so"
    token_label = "hsm_test"
    user_pin = "userpin"
}
```` 
   The following table describes the plugin configurations:
   
| Configuration	| Description |
| --- | ---|
|pluginName|A unique name that describes the plugin|
|pluginCmd|Path to the plugin binary|
|pluginChecksum|An optional sha256 of the plugin binary|
|pluginType|The plugin type|
|enabled|Boolean specifying if the plugin should be enabled.|
|pluginData|Plugin-specific configuration|


2. Copy the `hsm-keymanager` binary into `plugin_cmd`.

```
$ cp $GOPATH/src/github.com/seemenkina/hsm-keymanager/hsm-keymanager <path-to-plugin-binary>
```

3. In `/opt/spire/conf/server/server.conf` file, identify new `KeyManager` plugin configuration section:

````
KeyManager "hsmkeymanager" {
    plugin_cmd = "/root/go/bin/hsm-keymanager"
    plugin_data {
        hsm_path = "/usr/lib/softhsm/libsofthsm2.so"
        token_label = "key_test"
        user_pin = "userpin"
    }
}
````
