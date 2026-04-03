# Changelog

## 0.1.0 (2026-04-03)


### Features

* add CLI parity foundation for env/alias/bootstrap + strict sync parsing ([#2](https://github.com/jeduardo/lastpass-rs/issues/2)) ([f34c6bd](https://github.com/jeduardo/lastpass-rs/commit/f34c6bd610cf5eb8808e54478eac7040422d312d))
* added logout command ([cd1fa2c](https://github.com/jeduardo/lastpass-rs/commit/cd1fa2cfc276b73ad10ee7d6b2b0bc38e1528071))
* added missing items for password prompt and clipboard ([#10](https://github.com/jeduardo/lastpass-rs/issues/10)) ([f033347](https://github.com/jeduardo/lastpass-rs/commit/f03334759dbf6755e83c4569f38286fd79fb9c23))
* added prompt for master password ([209f62c](https://github.com/jeduardo/lastpass-rs/commit/209f62c58164f7364a379b0f282513dc58adbc02))
* added reference to project in version ([2aaba70](https://github.com/jeduardo/lastpass-rs/commit/2aaba70922a74376dcdce3fefd156ccbf5315cca))
* aligned colours and flags to upstream ([9bf7e1e](https://github.com/jeduardo/lastpass-rs/commit/9bf7e1e489f4fcb1f41703620225bfaee003746c))
* completed implementation of the login command ([2517013](https://github.com/jeduardo/lastpass-rs/commit/25170139e91c54fe46f7a8b7cd064005075aaaf9))
* full implementation of the logout command ([7a5bc38](https://github.com/jeduardo/lastpass-rs/commit/7a5bc382521409989a6dfe1df5edb6fc55354c31))
* implement add/edit/rm commands ([#1](https://github.com/jeduardo/lastpass-rs/issues/1)) ([e065848](https://github.com/jeduardo/lastpass-rs/commit/e0658484b4810560258b74ba9c103d3531ca4178))
* implemented share command ([#8](https://github.com/jeduardo/lastpass-rs/issues/8)) ([881758c](https://github.com/jeduardo/lastpass-rs/commit/881758cb29ad2ba69820efef61ea1f58fdd199d1))
* initial implementation for new commands ([ae20450](https://github.com/jeduardo/lastpass-rs/commit/ae204501691a9532c530795e61600636dbbf1437))
* parity for generate command ([#5](https://github.com/jeduardo/lastpass-rs/issues/5)) ([c90f87d](https://github.com/jeduardo/lastpass-rs/commit/c90f87dbac3d195b230063795c6796bde9cfefdc))
* passwd command parity ([#7](https://github.com/jeduardo/lastpass-rs/issues/7)) ([5aca5aa](https://github.com/jeduardo/lastpass-rs/commit/5aca5aaaa33a29d3eaf575807888a92a64620f4d))
* shared-folder move parity for mv ([#11](https://github.com/jeduardo/lastpass-rs/issues/11)) ([d21957a](https://github.com/jeduardo/lastpass-rs/commit/d21957a29da7edcece33eb9eb60852011efe6da8))
* **show:** show command parity with upstream ([#4](https://github.com/jeduardo/lastpass-rs/issues/4)) ([0973264](https://github.com/jeduardo/lastpass-rs/commit/0973264b63080fb7556660bd7c6170612cfc18fc))
* strict CLI option and color parity ([#13](https://github.com/jeduardo/lastpass-rs/issues/13)) ([c98251b](https://github.com/jeduardo/lastpass-rs/commit/c98251b309042582db48d305202afde092ab8026))
* sync/import/export parity with upstream ([#6](https://github.com/jeduardo/lastpass-rs/issues/6)) ([6f21cf8](https://github.com/jeduardo/lastpass-rs/commit/6f21cf89bf45f8e3a093777581b1c25e889a6873))
* sync/share parity across blob loading and commands ([#3](https://github.com/jeduardo/lastpass-rs/issues/3)) ([585d12a](https://github.com/jeduardo/lastpass-rs/commit/585d12af50f071f55ae53c0b516e8aa5b7fb1737))


### Bug Fixes

* align trust label + blob handling with C client; zeroize login password ([6f972f1](https://github.com/jeduardo/lastpass-rs/commit/6f972f1e0dc814aad7ba564024a83899b2ec5490))
* dropped unknown upstream command ([1324ded](https://github.com/jeduardo/lastpass-rs/commit/1324ded9796cfcc399a3116f6d59af7eee31f155))
* ensure only the env var from upstream is considered for key input ([36fb027](https://github.com/jeduardo/lastpass-rs/commit/36fb0274ef3767eb77f71faa96b4bce884fabd1b))
* restored shorthands ([2b258ea](https://github.com/jeduardo/lastpass-rs/commit/2b258ea6873fb14f72298a0e9712e97f16ad5702))
* security mitigations from 2026-03-25 review ([#16](https://github.com/jeduardo/lastpass-rs/issues/16)) ([f639280](https://github.com/jeduardo/lastpass-rs/commit/f639280e29471d6d04a2404d2ae04593dfee0ab8))
