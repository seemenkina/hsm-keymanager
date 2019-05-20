# hsm-keymanager

## Compiling the Plugin

    $ git clone https://github.com/seemenkina/hsm-keymanager
    $ cd $GOPATH/github.com/seemenkina/hsm-keymanager
    $ go build .

## Configure SPIRE

1. Copy the `hsm-keymanager` binary into `$GOPATH/bin`.

``
    $ cp $GOPATH/src/github.com/seemenkina/hsm-keymanager/hsm-keymanager $GOPATH/bin
``

2. Copy a config file `hsm-keymanager.hcl` in the `/opt/spire/conf/server/plugin` directory.

```
    $ cp $GOPATH/src/github.com/seemenkina/hsm-keymanager/hsm-keymanager.hcl /opt/spire/conf/server/plugin
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
