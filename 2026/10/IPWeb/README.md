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
| cai\[.\]bestipip\[.\]com:16000/UDP | Protocol-confirmed Solo controller discovered through Hunt.io |
| kk\[.\]bestipip\[.\]com:16000/UDP | Protocol-confirmed Solo controller discovered through Hunt.io |
| rao\[.\]bestipip\[.\]com:16000/UDP | Hard-coded alternate BestIPIP Solo controller |
| song\[.\]bestipip\[.\]com:16000/UDP | Hard-coded and sandbox-observed Mzmess BMW controller |
| ss\[.\]bestipip\[.\]com:16000/UDP | Protocol-confirmed Solo controller discovered through Hunt.io |
| us\[.\]bestipip\[.\]com:16000/UDP | Protocol-confirmed Solo controller discovered through Hunt.io |
| user\[.\]bestipip\[.\]com:16000/UDP | Protocol-confirmed Solo controller discovered through Hunt.io |
| xiaoyu\[.\]bestipip\[.\]com:16000/UDP | Protocol-confirmed Solo controller discovered through Hunt.io |

All nine controllers completed two independent APsolo registration exchanges
and returned active relays on 2026-10-01.

| IP Address | Country | ASN | Organization | Description |
| :---- | :---- | :---- | :---- | :---- |
| 172\[.\]236\[.\]129\[.\]220:23010/TCP | SG | AS63949 | Linode | Observed dynamically assigned IPWeb relay |
| 172\[.\]236\[.\]141\[.\]159:23018/TCP | SG | AS63949 | Linode | Observed dynamically assigned IPWeb relay |
| 172\[.\]237\[.\]65\[.\]208:23007/TCP | SG | AS63949 | Linode | Observed dynamically assigned IPWeb relay |
| 172\[.\]237\[.\]89\[.\]186:23005/TCP | SG | AS63949 | Linode | Observed dynamically assigned IPWeb relay |
| 172\[.\]237\[.\]95\[.\]188:23012/TCP | SG | AS63949 | Linode | Observed dynamically assigned IPWeb relay |

| IP Address | Port Range | Country | ASN | Organization | Description |
| :---- | :---- | :---- | :---- | :---- | :---- |
| 104\[.\]64\[.\]217\[.\]91 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | Dynamically assigned APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]217\[.\]99 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | Dynamically assigned APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]217\[.\]109 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | Dynamically assigned APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]221\[.\]83 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | Dynamically assigned APSolo relay observed 2026-09-23 |
| 104\[.\]64\[.\]221\[.\]88 | 23001-23020/TCP | SG | AS63949 | Akamai Technologies, Inc. | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]129\[.\]220 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]130\[.\]253 | 23001-23010, 23012-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay; exact protocol verified 2026-10-01 |
| 172\[.\]236\[.\]132\[.\]235 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]141\[.\]159 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]142\[.\]113 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]142\[.\]220 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]147\[.\]28 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]149\[.\]174 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]154\[.\]29 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]154\[.\]65 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]155\[.\]38 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]157\[.\]91 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]236\[.\]157\[.\]170 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]65\[.\]154 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]65\[.\]208 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]69\[.\]4 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]179 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]219 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]229 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]72\[.\]250 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]74\[.\]31 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]69 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]70 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]92 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]100 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]183 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]195 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]79\[.\]196 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]81\[.\]16 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]84\[.\]41 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]86\[.\]149 | 23001-23013, 23015-23019/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay; exact protocol verified 2026-10-01 |
| 172\[.\]237\[.\]89\[.\]186 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]89\[.\]217 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]90\[.\]102 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]34 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]43 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]89 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]184 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |
| 172\[.\]237\[.\]95\[.\]220 | 23001-23020/TCP | SG | AS63949 | Linode | Dynamically assigned APSolo relay observed 2026-09-23 |

All other endpoints in the range table returned the exact APsolo server-check
response twice on 2026-10-01. Ports `172.236.130.253:23011`,
`172.237.86.149:23014`, and `172.237.86.149:23020` were inactive and are
excluded above.

**Newly observed active relay pool**

| IP Address | Confirmed TCP Ports | Last Verified |
| :---- | :---- | :---- |
| 104\[.\]105\[.\]6\[.\]17 | 23001-23020 | 2026-10-01 |
| 104\[.\]105\[.\]6\[.\]249 | 23001-23020 | 2026-10-01 |
| 104\[.\]105\[.\]10\[.\]173 | 23001-23013, 23015-23020 | 2026-10-01 |
| 104\[.\]105\[.\]10\[.\]184 | 23001-23020 | 2026-10-01 |
| 104\[.\]105\[.\]10\[.\]221 | 23001-23020 | 2026-10-01 |
| 104\[.\]105\[.\]10\[.\]233 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]163\[.\]154 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]172\[.\]148 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]174\[.\]208 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]174\[.\]86 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]175\[.\]40 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]175\[.\]58 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]176\[.\]164 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]182\[.\]88 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]183\[.\]101 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]186\[.\]85 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]186\[.\]136 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]186\[.\]219 | 23001-23020 | 2026-10-01 |
| 172\[.\]232\[.\]186\[.\]254 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]232\[.\]13 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]236\[.\]145 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]238\[.\]60 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]238\[.\]67 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]238\[.\]93 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]238\[.\]104 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]246\[.\]130 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]246\[.\]187 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]250\[.\]19 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]250\[.\]27 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]250\[.\]224 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]252\[.\]14 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]76 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]129 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]161 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]162 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]171 | 23001-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]185 | 23001-23006, 23008-23020 | 2026-10-01 |
| 172\[.\]234\[.\]253\[.\]238 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]193\[.\]64 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]193\[.\]95 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]193\[.\]107 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]193\[.\]148 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]200\[.\]192 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]200\[.\]212 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]204\[.\]14 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]204\[.\]43 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]204\[.\]182 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]204\[.\]186 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]219\[.\]169 | 23001-23020 | 2026-10-01 |
| 172\[.\]236\[.\]219\[.\]207 | 23001-23020 | 2026-10-01 |
| 172\[.\]238\[.\]47\[.\]157 | 23001-23020 | 2026-10-01 |
| 172\[.\]238\[.\]49\[.\]82 | 23001-23020 | 2026-10-01 |
| 172\[.\]238\[.\]52\[.\]99 | 23001-23020 | 2026-10-01 |
| 172\[.\]238\[.\]120\[.\]152 | 23001-23020 | 2026-10-01 |
| 172\[.\]239\[.\]171\[.\]211 | 23001-23020 | 2026-10-01 |

The expansion scan tested all TCP ports from 23001 through 23020 across 49
`/24` networks already containing confirmed APsolo relays: 248,920 endpoints
in total. Only the 1,995 endpoints on 100 hosts that returned the exact APsolo
server-check twice are included. Ports `104.105.10.173:23014`,
`172.234.253.185:23007`, `172.236.130.253:23011`,
`172.237.86.149:23014`, and `172.237.86.149:23020` were inactive.

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
| [036c3ce965cf4bad3c652e36e4ecb806](https://www.virustotal.com/gui/file/036c3ce965cf4bad3c652e36e4ecb806) |
