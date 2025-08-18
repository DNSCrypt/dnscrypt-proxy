# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] - 2025-08-17

[1.9.0]: https://github.com/powerman/check/compare/v1.8.0..v1.9.0

## [1.8.0] - 2024-10-25

### 📚 Documentation

- **(README)** Update by @powerman in [5382254]

### 📦️ Dependencies

- **(deps)** Bump google.golang.org/grpc from 1.53.0 to 1.56.3 by @dependabot[bot] in [#89]
- **(deps)** Bump golang.org/x/sys from 0.6.0 to 0.26.0 by @dependabot[bot] in [#86]
- **(deps)** Bump github.com/smartystreets/goconvey from 1.7.2 to 1.8.1 by @dependabot[bot] in [#85]
- **(deps)** Bump google.golang.org/protobuf from 1.30.0 to 1.34.2 by @dependabot[bot] in [#87]

[1.8.0]: https://github.com/powerman/check/compare/v1.7.0..v1.8.0
[#89]: https://github.com/powerman/check/pull/89
[#86]: https://github.com/powerman/check/pull/86
[#85]: https://github.com/powerman/check/pull/85
[#87]: https://github.com/powerman/check/pull/87
[5382254]: https://github.com/powerman/check/commit/538225430af4489a383c36a15c23e6ef4dc86ca0

## [1.7.0] - 2023-03-18

### 🔔 Changed

- Err support multi-errors and errors.Is by @powerman in [6b218cd]

[1.7.0]: https://github.com/powerman/check/compare/v1.6.0..v1.7.0
[6b218cd]: https://github.com/powerman/check/commit/6b218cd72255955ba0504260a4f1159145534f19

## [1.6.0] - 2021-08-15

### 🔔 Changed

- DeepEqual supports .Equal method by @powerman in [#27]

[1.6.0]: https://github.com/powerman/check/compare/v1.5.0..v1.6.0
[#27]: https://github.com/powerman/check/pull/27

## [1.5.0] - 2021-07-02

### 🚀 Added

- Add MustAll by @powerman in [81cbe58]

[1.5.0]: https://github.com/powerman/check/compare/v1.4.0..v1.5.0
[81cbe58]: https://github.com/powerman/check/commit/81cbe586fde79267a5fe0dd3111f93cb83589c8d

## [1.4.0] - 2021-06-27

### 🚀 Added

- Add Error by @powerman in [63f7b90]

[1.4.0]: https://github.com/powerman/check/compare/v1.3.1..v1.4.0
[63f7b90]: https://github.com/powerman/check/commit/63f7b9084df9d1ea7a5d0aa7705b9f21e9ad6719

## [1.3.1] - 2021-02-01

### 🐛 Fixed

- **(Err)** Report actual error instead of unwrapped by @powerman in [6fa4756]

[1.3.1]: https://github.com/powerman/check/compare/v1.3.0..v1.3.1
[6fa4756]: https://github.com/powerman/check/commit/6fa475608450c67fba35c3377f84db58ac6f7a5e

## [1.3.0] - 2020-11-05

### 🚀 Added

- Add protobuf and gRPC support by @powerman in [#6]

[1.3.0]: https://github.com/powerman/check/compare/v1.2.1..v1.3.0
[#6]: https://github.com/powerman/check/pull/6

## [1.2.1] - 2019-11-07

### 🚀 Added

- Add support for windows by @alisonatwork in [93aa4b1]

[1.2.1]: https://github.com/powerman/check/compare/v1.2.0..v1.2.1
[93aa4b1]: https://github.com/powerman/check/commit/93aa4b156beb819afc8868dd547c52bf9ce65a38

## [1.2.0] - 2019-10-30

### 🚀 Added

- Add support for errors.Unwrap by @powerman in [b24f303]

[1.2.0]: https://github.com/powerman/check/compare/v1.1.0..v1.2.0
[b24f303]: https://github.com/powerman/check/commit/b24f303f46c22a6f30a99e37e1ecfb4bad78f48c

## [1.1.0] - 2019-05-26

### 🚀 Added

- Add errors.Cause support by @powerman in [4cdcdfb]

[1.1.0]: https://github.com/powerman/check/compare/v1.0.1..v1.1.0
[4cdcdfb]: https://github.com/powerman/check/commit/4cdcdfb6ede67672b4dc8283df66078b36eb0a85

## [1.0.1] - 2018-11-13

[1.0.1]: https://github.com/powerman/check/compare/v1.0.0..v1.0.1

## [1.0.0] - 2018-11-10

### 🔔 Changed

- Add coveralls by @powerman in [016f18f]
- Replace T{} with added T(), add TODO() by @powerman in [cb216a7]
- Improve doc by @powerman in [24d5c10]
- Report todo tests by @powerman in [cd799c8]
- Update Contents by @powerman in [00da268]
- Update doc by @powerman in [abb19f7]
- Improve report formatting by @powerman in [2981353]
- Improve Equal tests by @powerman in [8f8bdc0]
- Improve BytesEqual tests by @powerman in [4c17639]
- Improve Contains tests by @powerman in [f8dc6ad]
- Improve HasKey tests by @powerman in [a8642a1]
- Comment unsafe by @powerman in [bf0888e]
- Improve Len tests by @powerman in [4a9ef6c]
- Improve tests by @powerman in [75a9524]
- Improve numeric tests by @powerman in [64af321]
- Mark failed todo checker names with TODO by @powerman in [c754721]
- Improve HasType tests by @powerman in [c392d93]
- Cleanup tests by @powerman in [034b842]
- Improve test coverage by @powerman in [e36403b]
- Improve reporting to goconvey by @powerman in [b2ac659]
- Add GO_TEST_COLOR by @powerman in [13aa1c9]
- Add go.mod by @powerman in [e6010ba]

### 🐛 Fixed

- Fix isZero by @powerman in [199e5c9]

[1.0.0]: https://github.com/powerman/check/compare/v0.9.0..v1.0.0
[016f18f]: https://github.com/powerman/check/commit/016f18fc814098da2756aada4b6a9522a3b4e96d
[cb216a7]: https://github.com/powerman/check/commit/cb216a75e3f2347eec4a14ff01e5bf5fd1f94a99
[24d5c10]: https://github.com/powerman/check/commit/24d5c10044bbebb4b75e3920af404313712704e8
[cd799c8]: https://github.com/powerman/check/commit/cd799c8b7f8da7927d7337a88010554c758910c0
[00da268]: https://github.com/powerman/check/commit/00da26874f019617f0a41ac1c582cb9c433a1bd1
[abb19f7]: https://github.com/powerman/check/commit/abb19f7653dc87a5c7de041f707635d4bb8e863f
[2981353]: https://github.com/powerman/check/commit/29813538efb3d015db9b41ec1839b9f69790412d
[8f8bdc0]: https://github.com/powerman/check/commit/8f8bdc0a029ce0fd04f3e7ce8f741b63d36a4bba
[4c17639]: https://github.com/powerman/check/commit/4c17639100b5d836956b76c2729863f3452272b6
[f8dc6ad]: https://github.com/powerman/check/commit/f8dc6adc4949c732e73940792056c4e1c6218c9f
[a8642a1]: https://github.com/powerman/check/commit/a8642a196813c7966df46da39d0f0acf793b1803
[bf0888e]: https://github.com/powerman/check/commit/bf0888e342b03df85485057473edcc2a9e866f17
[199e5c9]: https://github.com/powerman/check/commit/199e5c94e048db83ddc3af4810a5e2c57de9c9dc
[4a9ef6c]: https://github.com/powerman/check/commit/4a9ef6c07b9cd3cdd9aec428927969701d685a42
[75a9524]: https://github.com/powerman/check/commit/75a952452d58defc33e3b1259d02a13d888af2e7
[64af321]: https://github.com/powerman/check/commit/64af321e259b79113aad6726363e68bf0aee43f6
[c754721]: https://github.com/powerman/check/commit/c754721f7011e998b745bdac46e85b2798b38f0f
[c392d93]: https://github.com/powerman/check/commit/c392d93333291f11934d8bf7f8b5aea5caa5454e
[034b842]: https://github.com/powerman/check/commit/034b842a504a77b0f346d7dc0236b554bfd62cba
[e36403b]: https://github.com/powerman/check/commit/e36403b215233f8c2936fab4ac1170e197e7f84a
[b2ac659]: https://github.com/powerman/check/commit/b2ac65961bc056b651fbd0b679fdd70ac1644b1b
[13aa1c9]: https://github.com/powerman/check/commit/13aa1c931498ded72df7cfff481a867aa5ee04d4
[e6010ba]: https://github.com/powerman/check/commit/e6010baaadc2fdbc65753f30c703234a0747d33f

## [0.9.0] - 2017-12-25

### 🔔 Changed

- Initial commit by @powerman in [f213e1d]
- Initial implementation by @powerman in [443b1ce]
- Add circleci by @powerman in [91c338e]
- Require Go 1.9 by @powerman in [a7b7545]
- Match(nil, regex) always fail by @powerman in [5381196]
- Improve expected/actual output, add diff by @powerman in [6c0f9d7]
- Improve dump formatting by @powerman in [9ba9a08]
- More doc. Fix Nil. Change Panic. New checkers. by @powerman in [be74982]
- Cleanup by @powerman in [20a9c7b]
- Update README by @powerman in [3dbd1b9]
- Update README by @powerman in [d5af7ef]
- Update README by @powerman in [5f59a20]
- Add colors in terminal by @powerman in [712bbb9]
- Add support for custom checkers by @powerman in [4c16b2b]
- Add checks: less/greater/etc. by @powerman in [21a821f]
- More doc/tests by @powerman in [c71eac7]
- Simplify Should by @powerman in [f06f74c]
- Contains use map values, add HasKey by @powerman in [25b2fd8]
- Relax matching .(string) by @powerman in [e1ee2a4]
- Equal support time by @powerman in [a1c5d26]
- NotEqual support time by @powerman in [6b906e7]
- Less/Greater support time by @powerman in [11bec60]
- Add Between by @powerman in [de3c52b]
- Add HasPrefix/HasSuffix by @powerman in [dcfb512]
- Add JSONEqual by @powerman in [90ef3c5]
- Add HasType, Implements by @powerman in [e3f7879]
- Add InDelta by @powerman in [2a81110]
- Add InSMAPE by @powerman in [08a829d]
- Update README by @powerman in [ed10da8]
- Update doc formatting by @powerman in [65bc32b]
- Update README by @powerman in [a2866ee]
- Add contents by @powerman in [ddcdd86]

[0.9.0]: https://github.com/powerman/check/compare/%40%7B10year%7D..v0.9.0
[f213e1d]: https://github.com/powerman/check/commit/f213e1d4629aa64b98cd73fb019308e48e11aaf1
[443b1ce]: https://github.com/powerman/check/commit/443b1ce9f3037526fe7fbc3eac91b87fe82a032c
[91c338e]: https://github.com/powerman/check/commit/91c338eaedd4ead4503881818182efe316b2700f
[a7b7545]: https://github.com/powerman/check/commit/a7b7545d622cf15d1fdb79710f9c5fa18faa85f5
[5381196]: https://github.com/powerman/check/commit/53811967f8ce1c77d0cfcbb877153e430ad61636
[6c0f9d7]: https://github.com/powerman/check/commit/6c0f9d7635984e409a45db8a24bccceead4050ac
[9ba9a08]: https://github.com/powerman/check/commit/9ba9a08c77daf96af405f46627ada24c94b6b4b3
[be74982]: https://github.com/powerman/check/commit/be7498261cb64ce24a6201a1ba7f49804e8b0e79
[20a9c7b]: https://github.com/powerman/check/commit/20a9c7b7b34612b07cbca7e9e727f0797eff3c78
[3dbd1b9]: https://github.com/powerman/check/commit/3dbd1b9d43df77bae925f19a332dcf5c91bf3fb3
[d5af7ef]: https://github.com/powerman/check/commit/d5af7ef4a3923abbf385869bf464a91c3188bd4a
[5f59a20]: https://github.com/powerman/check/commit/5f59a20447218bf5661d3be595192e6dcbff3e04
[712bbb9]: https://github.com/powerman/check/commit/712bbb9db5cdc781620982198c9bcafff40b3163
[4c16b2b]: https://github.com/powerman/check/commit/4c16b2bb7c992a308132c409be79f3d42f8c1473
[21a821f]: https://github.com/powerman/check/commit/21a821f9da895018beceb7e904456f9e7c207c0d
[c71eac7]: https://github.com/powerman/check/commit/c71eac7a87b4eab46a4571bc58f89bd9b32de965
[f06f74c]: https://github.com/powerman/check/commit/f06f74c8b812172a0e7c8c5a14f7fbfe9f38839e
[25b2fd8]: https://github.com/powerman/check/commit/25b2fd8b4f4ad38dd93968ff0e81836ee3b2c635
[e1ee2a4]: https://github.com/powerman/check/commit/e1ee2a48bee4d6063ea3792d64bb8f214b0f99aa
[a1c5d26]: https://github.com/powerman/check/commit/a1c5d26178621039643c1f3e3798d2da3c37cad1
[6b906e7]: https://github.com/powerman/check/commit/6b906e7eddee4d774177466166f6dcbea326e663
[11bec60]: https://github.com/powerman/check/commit/11bec60bb5cd00534dbbef375aafbf9c1a4518bb
[de3c52b]: https://github.com/powerman/check/commit/de3c52b30825e249a60be4e71b7fe59e0f56b0bc
[dcfb512]: https://github.com/powerman/check/commit/dcfb5120aac9f3ba08e4c4af65c75a2353b5b440
[90ef3c5]: https://github.com/powerman/check/commit/90ef3c5fa7c88c5638a39a951faceab833398e99
[e3f7879]: https://github.com/powerman/check/commit/e3f787991d2a75e36e0fa001e9c2412d47b17444
[2a81110]: https://github.com/powerman/check/commit/2a81110aaab1b0eb4d76f19b411f888a46aebdd4
[08a829d]: https://github.com/powerman/check/commit/08a829d719bc226044e45c9402435687beea9abe
[ed10da8]: https://github.com/powerman/check/commit/ed10da898ed1ad8f6361435dd38de7c9953e5e4f
[65bc32b]: https://github.com/powerman/check/commit/65bc32b096959cf93322c7f2a30c31dffe2ceeca
[a2866ee]: https://github.com/powerman/check/commit/a2866eecb8fc7119954e82a2a3f3bb2fc6520cde
[ddcdd86]: https://github.com/powerman/check/commit/ddcdd86d5f849a577909e69194088f93c5ca4d51

<!-- generated by git-cliff -->
