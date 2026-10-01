# IPWeb: Peering from Within

[Report](https://synthient.com/blog/ipweb-peering-from-within)

**Preserved Source**

| Name | Archive | Example |
| :---- | :---- | :---- |
| imzhuli/APSolo | [imzhuli-APSolo.zip](imzhuli-APSolo.zip) | TBD |
| imzhuli/CoreX | [imzhuli-CoreX.zip](imzhuli-CoreX.zip) | TBD |
| imzhuli/MiniPP\_R | [imzhuli-MiniPP\_R.zip](imzhuli-MiniPP_R.zip) | TBD |
| imzhuli/PP2 | [imzhuli-PP2.zip](imzhuli-PP2.zip) | TBD |
| imzhuli/PP3 | [imzhuli-PP3.zip](imzhuli-PP3.zip) | TBD |
| imzhuli/try\_auto\_deploy | [imzhuli-try\_auto\_deploy.zip](imzhuli-try_auto_deploy.zip) | TBD |

## Indicators of Compromise and Observables

**Observables**

**Network Based Observables**

| Domain | Description |
| :---- | :---- |
| bmw\[.\]bestipip\[.\]com:16000/UDP | Hard-coded BMW Solo controller |
| o\[.\]fecebbk\[.\]xyz:16000/UDP | Hard-coded CD32 registration controller used by builds 24032810118 and 24032810123 |
| rao\[.\]bestipip\[.\]com:16000/UDP | Hard-coded alternate BestIPIP Solo controller |
| song\[.\]bestipip\[.\]com:16000/UDP | Hard-coded and sandbox-observed Mzmess BMW controller |
| hs\[.\]hangzhouzhiqi\[.\]com:16000/UDP | Historical lx controller activated in later public APSolo source |

| IP Address | Country | ASN | Organization | Description |
| :---- | :---- | :---- | :---- | :---- |
| 34\[.\]237\[.\]159\[.\]252:11116/UDP | US | AS14618 | Amazon Technologies Inc. | Hard-coded two-stage registration service |
| 18\[.\]159\[.\]100\[.\]4:23002/TCP | DE | AS16509 | A100 ROW GmbH | Sandbox-assigned historical Mzmess BMW relay |
| 34\[.\]200\[.\]159\[.\]249:17776/UDP | US | AS14618 | Amazon Technologies Inc. | Recovered historical Solo registration profile; unavailable at last validation |
| 35\[.\]156\[.\]120\[.\]160:23008/TCP | DE | AS16509 | A100 ROW GmbH | Sandbox-assigned historical APSolo relay |
| 39\[.\]108\[.\]119\[.\]236:16000/UDP | CN | AS37963 | Aliyun Computing Co., LTD | Historical commented lx controller in public APSolo source |
| 44\[.\]205\[.\]227\[.\]254:16000/UDP | US | AS14618 | Amazon Data Services Northern Virginia | Sandbox-observed historical resolution for BMW 24032810107 |
| 44\[.\]208\[.\]74\[.\]237:16000/UDP | US | AS14618 | Amazon Data Services Northern Virginia | Sandbox-observed historical resolution for song\[.\]bestipip\[.\]com |
| 54\[.\]167\[.\]35\[.\]208:23007/TCP | US | AS14618 | Amazon Technologies Inc. | Sandbox-assigned historical Mzmess BMW relay |
| 113\[.\]105\[.\]101\[.\]59:16660/UDP | CN | AS4134 | CHINANET Guangdong province network | Historical of-test controller active in public APSolo commits |
| 120\[.\]77\[.\]66\[.\]5:16000/UDP | CN | AS37963 | Aliyun Computing Co., LTD | Historical commented bj-test controller in public APSolo source |
| 172\[.\]104\[.\]233\[.\]142:23004/TCP | DE | AS63949 | Linode | Sandbox-assigned historical APSolo relay |
| 172\[.\]233\[.\]232\[.\]130:23002/TCP | US | AS63949 | Linode | Sandbox-assigned historical APSolo relay |
| 172\[.\]233\[.\]232\[.\]130:23015/TCP | US | AS63949 | Linode | Sandbox-assigned historical APSolo relay |
| 172\[.\]236\[.\]129\[.\]220:23010/TCP | SG | AS63949 | Linode | Observed IPWeb relay |
| 172\[.\]236\[.\]141\[.\]159:23018/TCP | SG | AS63949 | Linode | Observed IPWeb relay |
| 172\[.\]237\[.\]65\[.\]208:23007/TCP | SG | AS63949 | Linode | Observed IPWeb relay |
| 172\[.\]237\[.\]89\[.\]186:23005/TCP | SG | AS63949 | Linode | Observed IPWeb relay |
| 172\[.\]237\[.\]95\[.\]188:23012/TCP | SG | AS63949 | Linode | Observed IPWeb relay |

| IP Address | Port Range | Country | ASN | Organization | Description |
| :---- | :---- | :---- | :---- | :---- | :---- |
| 104\[.\]64\[.\]217\[.\]91 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]217\[.\]99 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]217\[.\]109 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]221\[.\]83 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]221\[.\]88 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]129\[.\]220 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]130\[.\]253 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]132\[.\]235 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]141\[.\]159 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]142\[.\]113 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]142\[.\]220 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]147\[.\]28 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]149\[.\]174 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]154\[.\]29 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]154\[.\]65 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]155\[.\]38 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]157\[.\]91 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]157\[.\]170 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]65\[.\]154 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]65\[.\]208 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]69\[.\]4 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]179 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]219 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]229 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]250 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]74\[.\]31 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]69 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]70 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]92 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]100 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]183 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]195 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]196 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]81\[.\]16 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]84\[.\]41 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]86\[.\]149 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]89\[.\]186 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]89\[.\]217 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]90\[.\]102 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]34 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]43 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]89 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]184 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]220 | 23001-23020/TCP | SG | AS63949 | Linode | APSolo relay observed 2026-09-23 |

**File IOCs**

| Hash |
| :---- |
| [109f69b0c35ac0de9e2d69888b6f1fd949dae97a64d5c8483abdf9fba6e94f00](https://www.virustotal.com/gui/file/109f69b0c35ac0de9e2d69888b6f1fd949dae97a64d5c8483abdf9fba6e94f00) |
| [ee40c4fbad43bc4f34034a3d224efe71e8498c88d52a09088f8b2d00ee04199f](https://www.virustotal.com/gui/file/ee40c4fbad43bc4f34034a3d224efe71e8498c88d52a09088f8b2d00ee04199f) |
| [07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179](https://www.virustotal.com/gui/file/07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179) |
| [b84ccf36e373db0f1d41121e7d3ddc57a3e12aa4637b09c16fa88e96fa1cdf6c](https://www.virustotal.com/gui/file/b84ccf36e373db0f1d41121e7d3ddc57a3e12aa4637b09c16fa88e96fa1cdf6c) |
| [00f77813d48061fb4c2e374f531c6c0bc1dc45375366066f7e4147ef3ba0bbe8](https://www.virustotal.com/gui/file/00f77813d48061fb4c2e374f531c6c0bc1dc45375366066f7e4147ef3ba0bbe8) |
| [b7c7704d7cfb0a10db9a4c6900e8adacc4ee69c2ed9857675f2810f8271c7bf9](https://www.virustotal.com/gui/file/b7c7704d7cfb0a10db9a4c6900e8adacc4ee69c2ed9857675f2810f8271c7bf9) |
| [00ce33524815a7efbfabf08c88f2733f3f92bf1b43e32098f96fef91d43f817a](https://www.virustotal.com/gui/file/00ce33524815a7efbfabf08c88f2733f3f92bf1b43e32098f96fef91d43f817a) |
| [37ccf42fa41c9da423389035151d132aace739d7f11f8e229e5ef1ea1b54dd58](https://www.virustotal.com/gui/file/37ccf42fa41c9da423389035151d132aace739d7f11f8e229e5ef1ea1b54dd58) |
| [7d455bbc2f361c81d24ec14066790cf83d2b087e8b3aafb742e89e0d26f95c65](https://www.virustotal.com/gui/file/7d455bbc2f361c81d24ec14066790cf83d2b087e8b3aafb742e89e0d26f95c65) |
| [abcafc92a3fab6bbd78e33a3df03f69ac8934eee4a2d1a06eb040a9fec75b443](https://www.virustotal.com/gui/file/abcafc92a3fab6bbd78e33a3df03f69ac8934eee4a2d1a06eb040a9fec75b443) |
| [20662eb820289b35a263995dd898492008ed2e5f09132df49b210b73fd48afea](https://www.virustotal.com/gui/file/20662eb820289b35a263995dd898492008ed2e5f09132df49b210b73fd48afea) |
| [5e53cc7820e9ebbb104584375c921537d3f04918152089faddb94b9b978da025](https://www.virustotal.com/gui/file/5e53cc7820e9ebbb104584375c921537d3f04918152089faddb94b9b978da025) |
| [09435ce116f0e5a7d90dcb10f59ad18657a6a567d13b8e61a26f1e260eccc56d](https://www.virustotal.com/gui/file/09435ce116f0e5a7d90dcb10f59ad18657a6a567d13b8e61a26f1e260eccc56d) |
| [f9d4bfe942d1a6575f862d84dae5c116977fb0aa9c000fb45b64524936811543](https://www.virustotal.com/gui/file/f9d4bfe942d1a6575f862d84dae5c116977fb0aa9c000fb45b64524936811543) |
| [7f578fc1035df4fa2a762ecdcd7fe763c176a8ff4799cd15274a926ca936d53d](https://www.virustotal.com/gui/file/7f578fc1035df4fa2a762ecdcd7fe763c176a8ff4799cd15274a926ca936d53d) |
| [294319b32d8af7ba73a8e87312c50f1c87e300f5a724574a35bbaaf29485153e](https://www.virustotal.com/gui/file/294319b32d8af7ba73a8e87312c50f1c87e300f5a724574a35bbaaf29485153e) |
| [8ba4ca942c8ef7b844df8a98c7f6bc6de872c50beea65239194cabcdb71f4524](https://www.virustotal.com/gui/file/8ba4ca942c8ef7b844df8a98c7f6bc6de872c50beea65239194cabcdb71f4524) |
| [7a83708da58732571932c302038739f91a870b2f6f4e687c010ff4e7d86b0469](https://www.virustotal.com/gui/file/7a83708da58732571932c302038739f91a870b2f6f4e687c010ff4e7d86b0469) |
| [2a443baa14be4a2a45b7ea477a8ffc326169aaecc89919a42cf386d0978db0f2](https://www.virustotal.com/gui/file/2a443baa14be4a2a45b7ea477a8ffc326169aaecc89919a42cf386d0978db0f2) |
| [1069cae558acc0dbb7b1df930b6f280d877697562945e42669bf130bc0abb4ff](https://www.virustotal.com/gui/file/1069cae558acc0dbb7b1df930b6f280d877697562945e42669bf130bc0abb4ff) |
