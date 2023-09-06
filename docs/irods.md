# iRODS Storage backends

To connect SFTPGo to iRODS, you need to specify credentials and a `collection path`. For example, if your collection `some_collection` is under your account's home directory `/home/irods_user` in a zone `example_zone`, you have to set the `/example_zone/home/irods_user/some_collection`. If you want to specify a particular iRODS resource server to access, use `resource server`. You can set an empty string to `resource server` to use default resource server. An endpoint is host and port of an iRODS's catalog provider (also known as iCAT server). For example, `data.cyverse.org:1247` is the endpoint if you are connecting to [CyVerse Data Store](https://data.cyverse.org). Port can be omitted if the port is 1247.

Some SFTP commands don't work over iRODS:

- `chown` and `chmod` will fail. If you want to silently ignore these method set `setstat_mode` to `1` or `2` in your configuration file
- `symlink` and `readlink` are not supported
- opening a file for both reading and writing at the same time is not supported
- resuming uploads is not supported

Other notes:

- A local home directory is still required to store temporary files.
- Clients that require advanced filesystem-like features such as `sshfs` are not supported.
