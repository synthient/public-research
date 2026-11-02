# The Internals of a Badbox Operation

https://synthient.com/blog/the-internals-of-a-badbox-operation

## KM9PRO Device Specifications

Specifications of the research device analyzed in the report.

| Property | Value |
| --- | --- |
| Android ID | 44472cb9810a8444 |
| Board | HPR3A1325_4K |
| Brand | MeCool |
| Build Date | 2025-04-11 |
| Build Fingerprint | MECOOL/HPR311-MECOOL/RMQ:12/STTB.220726.001/C1.0.8_20250325:user/release-keys |
| Build ID | STTB.220726.001 |
| CPU | ARM Cortex-A55 (ARMv8), 4 cores, 32-bit mode (armeabi-v7a) |
| Device Codename | RMQ |
| ETH MAC | 0C:F0:7B:9B:24:3F |
| Firmware | C1.0.8_20250325 |
| Kernel | 5.10.226 (armv8l, SMP PREEMPT) |
| MAC OUI | 0CF07B |
| Manufacturer | SkyworthDigital |
| Model | UHD Google TV STB |
| MQTT ChipId | uhd_google_tv_stb-12502520307256 |
| Platform | Google TV (Android 12, SDK 31) |
| Product Name | HPR311-MECOOL |
| RAM | 2 GB (1966 MB) |
| Security Patch | 2025-02-05 |
| Serial | 12502520307256 |
| SoC | Realtek RTD1325 |
| Storage | 26 GB (eMMC) |

## Backdoored Device Models

Device model strings observed in the campaign, preserved with their original spelling and case. A model name alone is not sufficient to confirm compromise.

| Model |
| --- |
| 10P |
| 10S |
| 4K_Android_TV_Box |
| 4K_Google_TV_Box |
| 4K_Google_TV_Stick |
| 8S |
| 9088 |
| 9P |
| 9S |
| ABSL-216 |
| ABSL-432 |
| ABSL_432 |
| AHD9000 |
| APLAY4 |
| Aurora-1Gen |
| B11 |
| BC13 |
| BLUECOM_TV |
| BPTV30 |
| CBOX_3.0 |
| changshi |
| Cruze_Tv_Hybrid |
| Cruzetv_Hybrid_3_tuner |
| DongleTV1 |
| DREAMSTAR_A4 |
| DREAMSTAR_B_Series |
| DS4000 |
| E10 |
| E900V22C |
| ext-4K Android TV Box |
| FAS_K2150 |
| GI_UNI2 |
| GLBox_HD500 |
| Gpon_Y4 |
| H616 |
| HC1 |
| HD801_4K |
| HD890_4K |
| huayan |
| I-905 |
| IK-R8-2 |
| Impala |
| INTV-110 |
| INTV_1000 |
| INTV_ASIST |
| IPx1 |
| IPx3 |
| iX-MACAN |
| K5 |
| K7 |
| KA1 |
| KA2 |
| KARAxKARA |
| KD1 |
| KD2 |
| KD3 |
| KD5 |
| kh3 |
| KH3 |
| KH6 |
| kh9 |
| KII_PRO |
| KIII_PRO |
| KM1 |
| KM1_QM0202V |
| KM2 |
| KM21 |
| KM22 |
| KM22_PRO |
| KM23 |
| KM2PLUS |
| KM2PLUSDELUXE |
| KM3 |
| KM6 |
| KM7 |
| KM7PLUS |
| KM7SE |
| KM7SE_GTV |
| KM8 |
| KM8-ATV-MF |
| KM9 |
| KM9PRO |
| KM9PRO_MAX |
| KS3 |
| KT1 |
| KT2 |
| LEAP-S1 |
| Lite_3 |
| Lunn |
| M7.0 |
| M8S_PLUS |
| M8S_PLUS_DVB |
| M8S_PLUS_W |
| M8S_PRO_W |
| M8SPROW |
| MagicPlus |
| MAXIMUS |
| MAXIMUS_5.0 |
| MAXIMUS_6.0 |
| mbox |
| Mbox_VFD |
| Mbox_Y4 |
| Mbox_Y4_T2 |
| MECOOL |
| MEGA_PLUS_GOLD |
| MeGo1 |
| MEgo1_2K |
| MEgo1_4K |
| MI_Smart |
| MMC-B19 |
| MXV-4K |
| MyBox |
| NEK7 |
| NetUP_v.3.1. |
| NetUP_v.4.2. |
| Nitro_X3 |
| NL5H00X |
| NXMY |
| OCBN |
| ONSCREEN_Spark |
| OTT-5000 |
| PALFLIX |
| PDB-F2 |
| Prime_1.0 |
| PRO |
| PRO-C2 |
| PRO-M2 |
| PRO02 |
| Pulse |
| Pulse_Drop |
| q3-evo-1 |
| Q96MAX |
| QX1 |
| RL02 |
| ross |
| RS02 |
| RT-X3 |
| RT-X3GB |
| RT-X3K |
| RT-X3S |
| RT-X3V |
| RW01 |
| S12_PLUS_GOLD |
| S168 |
| S16_PLUS_GOLD |
| S16PlusGold |
| S905 |
| SA01 |
| SHOWBOX |
| ShowBox |
| skycom |
| SS-BOX1 |
| Steren_INTV_1000 |
| STV-3000_Plus |
| STV-3000Plus |
| STVB2 |
| SWITRON-i12L |
| SXYJ |
| T10 |
| t7_an400 |
| TBox_TV |
| TEH-500 |
| TEH-500_PLUS |
| Tesla |
| TK20_PRO |
| TV007 |
| TV008 |
| TV_Game_box |
| TV_Stick |
| TVCOM |
| TW.ONE |
| TW.two |
| TX3MINI |
| U10 |
| UHD_Google_TV_STB |
| ULTRA-LINK |
| V1 |
| Vala_Plus_4 |
| VBSL-217 |
| WR-370 |
| yitai |
| ZipSmart_Prime |


## File Observables

SHA-256 hashes identify the analyzed files. Dates and versions are retained as recorded in the source report. “Nexus Lineage” in the descriptions refers to the report’s Nexus section.

| Filename | Version | First Seen | SHA-256 | Description |
| --- | --- | --- | --- | --- |
| airship | N/A | 2025-05-09 | a15ba5616d6739ea21ba820057ee8b9c802c8caeefa50ee5af1424fc8592f5ac | Airship PCDN native agent; accepts controller RPC tasks and self-updates. |
| android-grass_v1.0.0_20250411_1222.apk | 1.0.0 | 2025-04-15 | 95dc587ade7d318c230e695d4b5283fb012c794be16e73bd1bedd90ea2d65ca6 | GetGrass proxy SDK module manager and status reporter. |
| android-grass_v1.0.0_20250417_1047.apk | 1.0.0 | 2025-04-17 | 2f21ad805f2d096b7912af89828709537e87a76f6728d6bdd1cc14b4614991ff | GetGrass proxy SDK manager and status reporter. |
| android-grass_v1.0.1_20250422_1819.apk | 1.0.1 | 2025-04-22 | fda3c8fdf7849814e270bbbc00adfa1e15ba8977f5b2508df5febf5dbd3075b2 | GetGrass proxy SDK manager and status reporter. |
| android-grass_v1.0.2_20250429_1858.apk | 1.0.2 | 2025-04-30 | fd09748eaa273ddfbcef463e17f94fce1ec03c4860350f5dd72980c01a413bcd | GetGrass proxy SDK manager and status reporter. |
| app-AOSP7-release.apk | 3.4 | 2026-09-28 | 89e16cd4e5d0b45cfac7d9badc98ad240a29bce4b761c0970f2fc7cbb14bf2a6 | NTP-branded carrier for TraffMonetizer proxy SDK. |
| app-GENERIC-1.0.2334.apk | 1.0.2334 | 2026-06-02 | fdedcaf3e211423e1bbea7e95087831d511ef36f84fb8151ffe3755d8f850139 | Fake Android netd service carrying Appsalt / Honeygain and TraffMonetizer proxy SDKs. |
| appdnschange-a7.apk | 2.1.0 | 2026-09-05 | 3ab311dd0e184b7767bc5d183dc68047c47ea6e7a1ada6f82cbb8496d2dedec5 | DNS Changer-branded carrier for Appsalt / Honeygain proxy SDK. |
| backup_7.jar | N/A | N/A | cd3a74800bcce0a4275e4ac16d087c2c5f8dc290480933cf4b3bdc1922851adc | Preserved ad and install module; Nexus execution unconfirmed. |
| com.abc.nexus | 1.4.6 | 2025-03-12 | d5a72e40f8821334ecfda30541435f8a9ad2fae1eb9aae133dd298bf1be374c7 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.4.6 | 2025-03-28 | 1f2ab93c35f0c37d9b88f82268183a2f77491aa6b142a48381524b18e217b960 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.5.3 | 2025-04-10 | a552bcb7d37c2bdb5c71e923157571598643de4051bfa3e5158fde3cb8709de7 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.5.4 | 2025-11-08 | 5547392697063aab2f2cf7510048c4e957181bfe99d12173671fd1528b77c309 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.4 | 2025-11-25 | 4e50013001ccbb89ddb707f9bcd41e3efbd408129bbbf75ba52293d343184cc3 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.4 | 2025-11-25 | 88e20768bc2d2be21d7eee04acb7b6f7e7cb0889828fff2045c4baa5a0311180 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.4 | 2025-11-25 | f2ed4a40fbb21d0560e82bdd2e85e825970d32052348241b487dd93191ebef2a | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.69 | 2026-01-13 | bc08f6e6f1f241fd5389eea9a95cbbdbbc21671e79d7ae40f0974e2f7902ca3d | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.70 | 2026-01-21 | 7eb1afbf4428a9a3b41a6faf9a7497aab1d7768a8370d475f580e574145a9e7d | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.68 | 2026-03-03 | 02b94ae4ee0fd2bab915fe2911d15ee70e51ca0564ba43c746593e7fe0b7ccd3 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.6.0303.rk7pro | 2026-03-09 | 83b3cfb7655483e0d421737c2bed707fdd1747f105deca6980233c011aaaea30 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.4 | 2026-03-11 | 0135b69bab304564628488829b825050d1dd6dab98e86ec6776839dac9365af9 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.4 | 2026-03-11 | db21164912998eeb3be7d4a9d8c7b965983a3f1c225f769014ea4eb910b03014 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.69 | 2026-03-23 | 69116e8f681ea312e7e9e3a8a436f66b3e98566c621412599ecaaa25348daadb | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.75 | 2026-03-23 | d4011b684ba389bf0b2dd8ded74fe8a4729b1cad4e6c18cfd928cb99a625a6e4 | Nexus host with Bird/AMH, TitanNet, APSolo, Jaguar, LinkFog, Moyu and LB102 modules. |
| com.abc.nexus | 1.7.81 | 2026-05-02 | e25616a0c64734f00d1f6dfb064d8f7bf1e4b95aac8b2e4aabb44b2950751bd0 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.89 | 2026-06-18 | cd8ef4ba20823b926b45a04946f24e45a7bcd4bf2bfc439cac8061a43f146903 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.88 | 2026-07-06 | 6c774014b6434dd34716426e30ee77a3528f35fca65e24c90dc93b002dba6fe2 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.6.2 | 2026-10-04 | b556d41c4fc56e6e6ab946ad42a13aa0b94d4bf027cc96fb02806d8c4efaf13f | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.71 | 2026-10-04 | f72bf627564753563cab3f4ca7fc473483b4abe9f723e388e8b9faa5f3d6cce2 | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.abc.nexus | 1.7.88 | 2026-10-04 | dcc4012e3a7838548a1e8a8c93e63f9671d6dbc9efcf0e661d9d0a6dd4cdee6e | Nexus host or OTA variant; see Nexus Lineage for version-specific SDKs. |
| com.oemservice | 5.5.6 | 2022-10-11 | 2d4b5c50e57e3e9b57d4ee02bef1dcd56163550a5e01c966e0f0fb6d46b2aeed | x.cpe device MQTT backdoor. |
| com.oemservice | 5.5.7 | 2022-11-09 | 99874d087e3f72a9d78439118361f438f7a156af318c788183d338cc315d7fa8 | x.cpe device MQTT backdoor. |
| com.oemservice | 5.5.8 | 2022-11-11 | 4fd0ddb15849137df77e8cb86cd951d2d220fd8dd5b8b03c5a7e23e815092fdd | x.cpe device MQTT backdoor. |
| com.oemservice | 6.4.2 | 2023-10-26 | cad908ad09d029971b24b4ad653fe680101ccaddd94b4e530c58bf45430fd1a4 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.0.20230804 | 2023-12-31 | 2a443baa14be4a2a45b7ea477a8ffc326169aaecc89919a42cf386d0978db0f2 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.7 | 2024-02-27 | 1c989cef1b9cc5a39715d172e3f3acb574a958765f4a9df50c952c0a359826cd | x.cpe device MQTT backdoor. |
| com.oemservice | 6.4.5 | 2024-03-23 | 3627f848804f49c041203e8d754e8d89f3ff6243b6d9e1ca6e50bbf08dbd9785 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.0.20230804.alpha | 2024-08-24 | 1c34f551cea557b24f6f3776de7fecaf40536c749d5b9734242acde4dd578c53 | x.cpe device MQTT backdoor. |
| com.oemservice | 1.2.1 | 2024-09-17 | 125647fbfb292715930cd52394f020c27e4f4488c1145afe62c0e6547b5aecae | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.0.20230804.alpha | 2024-11-16 | 7a83708da58732571932c302038739f91a870b2f6f4e687c010ff4e7d86b0469 | x.cpe device MQTT backdoor. |
| com.oemservice | 1.2.1 | 2025-06-28 | 7316469fd5b9fa633d9474a14b72716b9ceb4bbf656725ab79409da608eda2be | x.cpe device MQTT backdoor. |
| com.oemservice | 6.8.4 | 2025-12-22 | c57ab1b8e5ad806a850b5cf004fbb6779edf6d6e2948f3373766a509e0685ca1 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.8.4 | 2026-04-25 | 498d0862ce2ce972e9ac9bd3ea592b9f9cd8c5119dcc90fcb1b14a547889e9f9 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.8.4 | 2026-05-18 | c9baee088d95f24ea9945ba6f0f9f9d717680aaa4d347a42e912785338ac539f | x.cpe device MQTT backdoor. |
| com.oemservice | 6.9.2 | 2026-06-02 | b2e55884c819c210eaf46aeb7970a1ec623944b5d1a8c2178904f998b9682ac0 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.0.20230804.alpha | 2026-07-31 | f4c064e4e6e01b63f25162818a3e7672a2ee613d23b2b58b14bd0708d46b69c5 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.7 | 2026-10-04 | 0fe4c7d38a75b675e4d5b9528433a476ccde95616f7187040e6e4c4e1a5f388e | x.cpe device MQTT backdoor. |
| com.oemservice | 6.5.7 | 2026-10-04 | 5a6867298aba53866581d12fe67c563fd375101f8fcebbdc20579fdcc3b73732 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.6.0 | 2026-10-04 | caaa41d8246d2a21d55cab9b19749d2c636c7546ce42803e4ec380727e8af50a | x.cpe device MQTT backdoor. |
| com.oemservice | 6.8.3 | 2026-10-04 | 3ec2f3411720cdc3b3b6851d359c739ad1003eaa30a9c075dceac174431f1833 | x.cpe device MQTT backdoor. |
| com.oemservice | 6.9.2 | 2026-10-04 | 24646c9f4a7b2a1294810f7f3f4125fa21c36383459821b4d51c48375d94a493 | x.cpe device MQTT backdoor. |
| config_package_V20251125.01.tar.gz | N/A | 2025-11-25 | 235f2dcd66fdf4d9f19baa09148482c34295aaf05751290cbf9edb733b53858d | Historical Nexus installer and configuration archive. |
| EcoSaverDaemon-1.0.1-release.apk | 1.0.1 | 2026-07-03 | f4664b36802d585634a4217de9ac932564c26a64f4991ca3a8c98c891879b655 | Idle-launch and accessibility controller; earlier EcoSaver build. |
| EcoSaverDaemon-1.0.2-release.apk | 1.0.2 | 2026-07-09 | 762d37858b2c36daf19181cbe54777229e0ae710615d2b58b66dacc9d62f3c3f | Idle-launch guard and accessibility controller. |
| ElderTV-HC1-TOB-PREVIEW_v1.0.16_20251204_1044.apk | 1.0.16 | 2025-12-04 | 1e7849c9246f4ac20ca1ae857032c4be22d7f4ec8309f4a22d770019c96489e8 | ElderTV app-store, upgrade, and push client. |
| FreeTV_3.11.0_338.xapk | 3.11.0 | 2026-07-20 | 076becdc8e6586d48d9ac29b997f7a8d63687d44e76d6cf15826db13cd5e26e8 | FreeTV streaming app distributed as XAPK. |
| frp-lite.jar | N/A | N/A | fe5f3fbd9457d3b20f7afa83fc42d5feab1c1cbf4387c52a036f5c12f27a1e28 | FRP Lite reverse SOCKS5 facade; native engine downloaded separately. |
| grass_android_2.0 | 2.0 | 2025-04-22 | 306f1cde910ed32fb1adccc0101d315dcce18a3f7ca9cdd5f611007bbded02ce | GetGrass Go proxy engine embedded in Grass 1.0.1. |
| jaguar-mb002.jar | N/A | N/A | 00d2af00b7593f4468e3c9a1cfb1abd89042b6f629b1ec49b889a37cf838d5c7 | Jaguar Java TCP/UDP proxy SDK from a historical procedure. |
| kto.xapk | 7.0.7.3 | 2026-09-16 | 9fa7b23b68940ce247be3a126ab4fb38e0fb83c08156e842980ed4f506210d9f | KTO streaming app distributed as XAPK. |
| libbase.so | N/A | 2026-07-06 | 701f57169f3968bf412d33ec09fa6f2c11ece632aed9f44efa38eaf4fa2e08c6 | TraffMonetizer proxy engine embedded in Nexus 1.7.88 and NTP carrier. |
| libbase.so | N/A | 2026-06-02 | 6a44ce5695126cb3eb9f321c965fdd30c095a7b156821550923d27a4fc326790 | Distinct TraffMonetizer engine in fake netd carrier. |
| libjaguar.so | N/A | N/A | e2bfca7225af84f116de7ed10e4ad425d0ebfd6e19903d226b9768282865700f | Jaguar ARM32 native proxy asset embedded in Nexus; load not observed. |
| lw_android_agent_special_ndk_32_20250717 | N/A | 2025-07-17 | 859ae7a976ddde79173224c61c7cc493525ffbb1313b9af050238e7b03f27f28 | LinkFog native proxy agent. |
| lw_android_agent_special_ndk_64 | N/A | 2024-10-23 | 5a73a10e538d03ee6e140093ee9a71f028522eee8cdf4e1ced3dc2d50e3bfa29 | LinkFog native proxy agent. |
| MboxLauncher_v2.8.2_x3_pulse.apk | 2.8.2 | 2026-07-29 | cc7c8a4156550c463ecf3371203f8e49fc531f790c45e2636764018161c217c6 | Android TV launcher with package controls. |
| MboxLauncher_v2.8.3_x3_pulse.apk | 2.8.3 | 2026-08-06 | 2318bcc16444f8d5786ceb2b0a52a0078b8611071cb38f7349c7ebf920e3a623 | Android TV launcher with package controls. |
| media.player.mysplayer-v2.1.1.apk | 2.1.1 | 2025-08-19 | 2c9341ce6f3a6516056a94f0deb9f4bea679fd1806b305d2f1447c2020109c05 | TV media player app. |
| nat_checker_app.apk | 1.2 | 2025-05-10 | 157969b15197f046dd2cf99cd4ddd7a5e306f6d3ee2cc24a49128b9dc720d982 | Airship PCDN-related NAT utility; see extracted airship agent. |
| nat-checker | N/A | 2025-05-09 | a4dea3fa89e5b9aa5f49f8b3ba17837bc1094a7b2dff40eb640151086b6d4c61 | Native NAT checker bundled with the Airship agent. |
| nat-checker.apk | 1.1 | 2025-05-09 | 5e65bc7600e9e3c3c4439de00b57d83c8dc3ffaa4c3e0daade3fcf3d7e1eaba6 | Airship PCDN-related NAT utility; see extracted airship agent. |
| netflixhook.apk | 1.3 | 2026-09-05 | a6f403f6a85cc9e1610d383443637f94b751ae4cd36613d59280a40ce119f087 | Netflix Hook-branded carrier for Appsalt / Honeygain proxy SDK. |
| netflixservice.apk | 1.3 | 2026-09-05 | 9a3dd627ebb1ae1146215bf28aa2ddaa20de9e1720e19a43968021608c4fcd17 | Netflix-branded service carrying Appsalt / Honeygain proxy SDK. |
| ol_imp_30737.jar | N/A | N/A | 9d4ad1688c13d5acaa9ed6ad880d95f1a6c5aefd7388ec7ec78cecdfaea0f641 | Bird/AMH OL loader; contacts img[.]amhib[.]com for encrypted stage metadata. |
| OTA-RELEASE-VS-4_4_signed_for_pulse.apk | 4.4 | 2025-05-19 | e81124e06c95b32f59e31204c8b3f4570f0827ac9ecc8ee1ef983e34ff70467d | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-RELEASE-VS-4_5_signed_for_pulse.apk | 4.5 | 2025-05-21 | 8f81ee0363ab69a3dc02fb62f15e2b206c1cf3d54644e28c2957968de249d33a | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-RELEASE-VS-PROD-V4_1_signed_for_pulse.apk | 4.1 | 2025-04-28 | ae6bdb5cf4e81b12f6b4280873dae40aeae98ad77e25f8f7392b368c2063db17 | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-SERVICE-RELEASE-4-3_signed_for_pulse.apk | 4.3 | 2025-05-07 | 72a26baa932396f86342668c9f7878aa32c2a8165dbb5a9ccca205c8730e9609 | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-SERVICE-VIDEO-STRONG-V1_0726_andriod_p_signed.1.apk | 1.0 | 2025-07-26 | 8c2b6f4196ffd081e81e0f1671550666828b4b331f5d66fe8888ea617646b1d8 | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-SERVICE-VIDEO-STRONG-V1_0729_2_android_p_signed.apk | 1.0 | 2025-07-29 | edfb146f7269d5947e746695ce5a05886dd1ffa79f099f967e61bb0bece1e888 | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-SERVICE-VIDEO-STRONG-V2_0804_android_p_signed.apk | 2.0 | 2025-08-04 | 8e2c2812f64ebc8871470a349e402ebc52233c2d2162d0d937c7338bdcd4f834 | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-SERVICE-VIDEO-STRONG-V2_0804_h313_q.apk | 2.0 | 2025-09-02 | ddfc766fddae2127084a2f33d8c8fd32bb9b4fc43067054b3e5ddf411265d769 | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-SERVICE-VIDEO-STRONG-V2_android_p_signed.apk | 2.0 | 2025-08-01 | c400117b80f3278140b237a6e644bee688c1b80f93b15e23f3599fc58d76f90f | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| OTA-VS-RELEASE-PROD-V4_signed_for_pluse.apk | 4.0 | 2025-04-22 | a6c7ef9b6d5277dada145361164ff79e1e6c6be1cd28f6739113c72ee30ea4cc | Remote web-content runner; plays streams and simulates clicks or scrolling. |
| SdtCustomizationConfiguration.apk | 12 | N/A | c447cada10e84dd34ad0b9c64324c8454ebfaa8d16d8180557ab301e4b530317 | Skyworth OEM customization app; package com.sdt.customization. |
| SdtDeviceInfo.apk | 1.0.2 | N/A | 911363c00be445ed7f5dfcf04b573f7df24db2ad8b37e4cab87ecfc04d3de18b | Skyworth device information app; package com.sdt.deviceinfo. |
| SdtFrontPanelLedsService.apk | 2.2.9 | N/A | 4a65e1192ec312225565fb181c8582191f87db2e19904622c0acac4f277ec665 | Skyworth front panel LED service; package com.sdt.frontpanelledsservice. |
| SdtProductTest.apk | 2.3.4 | N/A | a592a1a11e6974c7127ece13c448bf7f19d6c98bb5a004df6ceda262221234f4 | Skyworth factory hardware test app; package com.sdt.producttest. |
| SdtRcuOtaActivity.apk | 1.1.3 | N/A | fd5e13883075856e0b888b228ecb0baaf040a7a8a5819037ff50dd81e6340ab3 | Skyworth remote control OTA user interface; package com.sdt.rcuotaActivity. |
| SdtRcuPair.apk | 1.4.2 | N/A | e6b88221c212cd20f565855421d1e0eaabeb373d6c5b9c7d4a63bd186c319e14 | Skyworth Bluetooth remote pairing app; package com.sdt.rcupair. |
| SdtRemoteControlOTA.apk | v1.1.7 | N/A | 9de24cb3de5bb9d48cd25099c75ee329efc964af6246db20570ebe446ea483a8 | Skyworth remote control firmware updater; package com.sdt.remotecontrolota. |
| SdtUpdate.apk | 2.5.1 | N/A | cab4eba0d550f9ec51497323b41280f8eed47eaa857742dafdfdad4d5b6ede87 | Skyworth OTA updater; package com.sdt.ota. |
| SmartEntertainment-v6.2.1.apk | 6.2.1 | 2025-07-23 | c6947bd4fbbe0e7d1d93029ca76c337aff2b2382bc6bbc7539ed478266ea350b | DeviceThread management and app installer client. |
| SmartPrivilege-v0.0.2.apk | 0.0.2 | 2025-07-23 | d3956318e649a325c4fe4a27c0e296f26f5cec6128b1c5c3a8dd041534e58a4a | Privileged local device-control service. |
| SmartThroughput-v1.0.0.apk | 1.0.0 | 2025-07-23 | fc452f9354fe667cfeb62a5edf5e5325e3c1abfa6df279dcf07b6c4a32a9b94f | DeviceThread network throughput utility. |
| static_host_20260206.jar | N/A | N/A | b9dfde7832038af8a21563dfc4a00b161f56d5afebce20ccbbcd3df4960c0696 | Preserved ad automation module; Nexus execution unconfirmed. |
| videoadtime_pproxy_32 | N/A | 2024-10-23 | 072826e0548641cb91d57f6dba8b00fa9c4f4000d4ef6490593e33cddb8d1208 | PLU/PProxy native relay executable. |
| videoadtime_pproxy_64 | N/A | 2024-10-23 | 206428965533b9eb3687a0c801a4c3059f7c33c076481f5c684b2e33afb5b242 | PLU/PProxy native relay executable. |
| WhaleTV_VS_ServiceScreenSaver_1.0.9_20260603_signed_aosp11.apk | 1.0.9 | 2026-06-12 | 56977decbbf31bf69fd31163b32e13cb4425929696973e4a2dbf2f83bb38e53d | Whale TV screensaver service. |
| WhaleTV_VS_ServiceScreenSaver_release_1.0.10_1001000_20260618_signed_aosp9.apk | 1.0.10 | 2026-06-26 | 069d829ae00fbfb40001877bb762f40bb798d018a6ba2fea08202d253bbff86e | Whale TV screensaver service. |
| x.cpe | 3.6.5 | 2020-12-14 | 677e64469956197d424186c0225020e22a48dab8309fa48ca50afd25d33f6c2d | x.cpe device MQTT backdoor. |
| x.cpe | 5.1.4 | 2021-11-17 | fcdb7dde95931219e5bb411907e50bdb0f048e4be9581b232dec55ebf2c6e486 | x.cpe device MQTT backdoor. |
| x.cpe | 3.6.5 | 2021-11-26 | 6d3fd13dd305a0a4f04e9f8f8c5d0605dafbb7f465ae78486d3a6ffe99f25170 | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.6 | 2021-12-14 | cdb1157fce2b87da5b646ff5440d1ca073a835d99c9fa0a47d5ff56321a6b6a0 | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.6 | 2021-12-17 | fa0406b5f3d7baf695f71cb1dd14fa065e1d8668dbf8409f93aa02a533916e6f | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.6 | 2021-12-29 | cd29655c3425bd756b9ef35c4b6cf9d39bdb474c570e9ec30560efe9844a7f26 | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.6 | 2022-01-07 | 98d7c1e8d06a82b986a087a63f73eaec593108ab63391206ec27681d9ccb2f11 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.0 | 2022-04-26 | 5b73e39f7fcfdc3d20b38a00e620e01a9078a8e92f888c456eaca0f78f5e7c6e | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.0 | 2022-04-26 | 9c24d3abc7aed4f5ef35fb5932e972010a30e8c94d345f72c16dd8c858d3ba7c | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.0 | 2022-05-13 | 1806a1a93a6bce28cc6e95e9001f06370eaef9c66846ade9aecaf220d7ac91a4 | x.cpe device MQTT backdoor. |
| x.cpe | 3.4.2 | 2022-06-17 | 76b4bf6f55aaab35428260a830ac9a2c437a09aefd521c5b51618db47beca3b2 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.2 | 2022-07-31 | 9216a0a460400403027d4dfc9a6193a776603b64735f174e74a89607567ac6f2 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.6 | 2022-10-10 | ce3d0683d57ea8eeebd2400cbe7f54347414930d28fa89fe6baa62bb566c6518 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.6 | 2022-10-29 | 7232cb8a2a0d0b6e21cfbeb70431ed8f1575b3dcbea2620e6aa6c04a02f656a9 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.6 | 2022-10-30 | 11a9f22718935389073301f616c7473f2afd90ae3582ea3011cf093eb422b7d6 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.7 | 2022-11-09 | 3e891f061daf73c2edc14ed98512cad008346679645e8165320bf96fb8b0e0d6 | x.cpe device MQTT backdoor. |
| x.cpe | 3.6.5 | 2022-11-10 | 4c46a10ec3a2deb77b59b25fe929e434a1126a0428d54baac1e6df769bf09358 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.8 | 2022-11-10 | 415d54757c2f96fd28404f1ab8da1e90297a381ec3d7fb47d33126644a0a421b | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.8 | 2022-11-10 | d70c53aa884fe7d0e41f09f609a96717bd7fb527e4d11986809b588f7ecd6122 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.8 | 2022-11-10 | facef2228db7b2c05d8a27552168b0c24c930794c8ca1ea1efff3960ef3e6f0e | x.cpe device MQTT backdoor. |
| x.cpe | 3.8.5 | 2022-11-19 | 2cdb1f0f0969766142f3debbab55eef5e24c15d49a513753f1f6b67bc3e8438b | x.cpe device MQTT backdoor. |
| x.cpe | 3.8.5 | 2022-11-30 | 3126aa30062459543fe6e7966255d236f43e64d649767eafffd627c5295649b5 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.8 | 2022-12-19 | 4e184ab960d6265e781921218375fbfaf7e835b54cb4b419a35cff99dd8c7fe1 | x.cpe device MQTT backdoor. |
| x.cpe | 5.1.4 | 2023-01-25 | 15b86359b9e124ddd8ec79f5f548c6f6fa154a7a9c400004f9f54b7760184e92 | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.2 | 2023-02-21 | 9df157f3975b582074033c80d0d586f3911fb6bd3813539e2edf87ada4eee9fb | x.cpe device MQTT backdoor. |
| x.cpe | 3.6.5 | 2023-03-23 | e0cad7b8380eb3529fcd11c50f6213c6b025c80000b1b5044f889f8da5dcd2c9 | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.3 | 2023-04-21 | be9990489fbf36100ec148f3a83795f2674d17063edb8accd560f1ce2f97dedd | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.5 | 2023-04-23 | 8953f9013eb8c31b27c86ba90edbdb9ecba216ed2cb6a992508c1964d53b8eee | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.0 | 2023-05-06 | 0ae9baf869a84df9bfec5da16db5a367cf13ac53b60a44859ad39b6801811ec9 | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.0 | 2023-06-11 | 6a995ad8cf248875b47f9d89518c7a21ec7cce2c252c181414e8935c6001ea36 | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.7 | 2023-12-14 | 247ee39703017b3eb5180b2d1c3b266dba7ef38475ca542d1e3f42e306293d5c | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.5 | 2023-12-26 | bb89b38b3319c9f077ac984c6458101be8a94935e5482eed83b5dfb9841804a2 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.6 | 2024-03-18 | f3a23ac708ab2d7dee24a9b0565bfc619b43d07b2665ee52ec8e853b8d5b6e46 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.6 | 2024-03-19 | 04ffe332458931d82c0503daba1859622540828302af1190d2d3c6447094428c | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.5 | 2024-03-23 | b01cd8e6c0828f03b0ed755cccd7f661f47e910aa6a8deddcb352dbaf4b01a35 | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.5 | 2024-03-23 | b9a193089f72a8dd6deae28b8e9665ba27337995a384a8f1edc3bcb712c01157 | x.cpe device MQTT backdoor. |
| x.cpe | 6.4.5 | 2024-03-23 | f69b8a1db8c79ecb6468ffbe147909c06da881486a935593909b76243131d82b | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.0 | 2024-03-23 | 01b8c78f5509119b3e27ea4d628048985b94b5e00db0431d843519cf1d3e2cde | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.0 | 2024-03-23 | 0e8c50362e263ad793fa154b8b86f279513764b65a3876ce7af079b95e130298 | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.0 | 2024-03-23 | 4f1e511e903ccc78e5500e82d08862da44a68b81a52f02754ed9a87c5cc5dc5e | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.0 | 2024-03-23 | b84ccf36e373db0f1d41121e7d3ddc57a3e12aa4637b09c16fa88e96fa1cdf6c | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.7 | 2024-03-23 | 21c46eacb2af06c0cd32e9078f056319acfa776466e7fb34ed4ae21c259adbf0 | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.7 | 2024-03-23 | b97fb1a0061083b0530190d9b12b0158b79dd31ea2cb4c6fb3a14d83d86d89ce | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.7 | 2024-04-03 | fda16bcd07a35d0cf19ea68ce7690111a32960afac5e45d25c44416004859d00 | x.cpe device MQTT backdoor. |
| x.cpe | 5.5.8 | 2024-04-04 | f3719a84e0a6f84544d313324b48a28b49f108119cc02a2ee5ac11a8ff6a1ed7 | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.7 | 2024-04-16 | bcf142ba37e897b7fcbb89353ec9b5a7c3bfb1d167838d3b91c347b9fdfb2230 | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.0 | 2024-06-14 | 35eb00285a8690d3c8d850ab041b486fd5a1001df922b0946f0d8cf6a0dd42d4 | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.0 | 2024-07-01 | 07b511a6f7715ccd2f77b5f51e4cf46542ccaada99564252711f4a142ac26179 | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.0 | 2024-11-07 | bb559084c622e505dac3a2a48c45561478f3cb40f9a5922c23b247ae8f38d5c5 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2025-03-12 | a710f0a2ffd64039137c4294ce14919067a8879cc0761d87f428b73a0839df5b | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2025-03-28 | 539913c9769de4c60151fd0c4dc5d5a669fbd48b64194b727f2f46e512e74b3f | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2025-04-16 | 62040f86c305952b997d2fcda166759cfe1d3f5f340df115d062a1932d53e466 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.5 | 2025-07-07 | 6f7f4b22eb7841d2b828f1eda77173880d42267a33b387bee9cee983c03bf291 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2025-11-08 | 02490fa9f472ec872723d64d03402967e77932d2df72c588b0d7a7df9e17ae62 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.6 | 2026-01-12 | 1de0a368599ab04b8863c0e61c2d5a75e00f742a3326325f2870a9a72ee8d200 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-01-26 | 270932e0857e2927e829f9d7eb62de15e2448049dbc2594c8760246229cbb678 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.6 | 2026-02-18 | c96e32f7cbb8dda3cfb1f94f2c3d51dbcb68e2e5879093e18385f0b8f3b1a63b | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.0 | 2026-03-08 | 5e9e0f8dc96fbf4d3e78dae90d434c424045c823316dea394e3ca39d97cda9bb | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-03-11 | 42f85b36642256475bce08627c152e76f8feb3d55c7754eb6b888fed617b5ff3 | x.cpe device MQTT backdoor. |
| x.cpe | 6.9.4 | 2026-06-18 | 486a784cbd6335d31214edd7bed7fcfb486b875374597c139826c77c91ccbbaa | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.4 | 2026-08-03 | 6b55b8b3ff7bd31af93b59612f0800c09e49d3badc772e2395736616c87d5612 | x.cpe device MQTT backdoor. |
| x.cpe | 5.4.6 | 2026-09-03 | 049b626ca9bc4cf552e675dd5bf6215753caa3a3d28fab17b2a8fa9e0c8421c0 | x.cpe device MQTT backdoor. |
| x.cpe | 6.5.7 | 2026-10-04 | 085662ba43e22d04d6f69b7b5176c68cedee6507c5d34973c94459f324b44c8d | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.2 | 2026-10-04 | 002ecacb7afe59836afc357074ea91308fd448b34dfdec0dc3d89f1bc15c1bb6 | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.2 | 2026-10-04 | 2a5c292620048066cec0206cd7d10ed44677ae27257c239867ba70695dfcc361 | x.cpe device MQTT backdoor. |
| x.cpe | 6.6.2 | 2026-10-04 | a4f62cd7e033d200f2a5c3f56bcbb470182ab22d82ec50ec578a07b39832dc0e | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.2 | 2026-10-04 | 760df0aa754e760342885ed289753dc8c9964ab2105b91953741b07a14b33328 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.2 | 2026-10-04 | e92df23222acf808b671b5fd0aebc60064efd080c1196ab0ada9c66c79a72c88 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 2aaa829447ae689d8b9bde422811c86ae67a5eee6acb63f269d773f7d6e73063 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 3584c0f9363c54defe00ba0c0c624274064d65274b1877ad9a00f0fee632c068 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 36dbe473ff1c2e87fc6fd3f2c2ae927c1370338825b419ce8f1ca353e6a3529f | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 4b84b48018f0a8019dfadbd4d19eae60b916ef4596e53e3a9bd0bd4c575a22de | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 5c6a20010d2eaac28831f28315ad3dba88c7187a09e4c6827818682066e0cfa0 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 6402c274920a0bc7ed5f980af814a7e75cb18cfdd11342bb8a4450bdcdcf86bb | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.3 | 2026-10-04 | 786061082203ba868710c94fbf6da04fb7535a4f4463e539d56d43bea2f5eeb6 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.8 | 2026-10-04 | 95b86ac9272bbc33016a812b39a9a77781d5f6f3173c4bdb0bd6b245549ba1f5 | x.cpe device MQTT backdoor. |
| x.cpe | 6.8.6 | 2026-10-07 | 41def231255a382906f058b19bcf4980011d40f864112a0834fed984ca41b97f | x.cpe device MQTT backdoor. |
| YokaTVScreen-release-.develop_adshow_uka.-PLATFORM._v1.8.3_20260911_1034.apk | 1.8.3 | 2026-09-23 | f225294f14edb651527661d7160513b682c2b27433448e0590d51eaada647cea | Ad-delivery screensaver; fetches ad placement rules and can report ad request/show events. |
| YokaTVScreen-release-.develop_adshow.-PLATFORM._v1.7.6_20260814_1402.apk | 1.7.6 | 2026-08-17 | 2f20c6f9071f255bc44c29d6add2a62eee4a5b265c25131ca84a06112f2a5ee3 | Ad-delivery screensaver; fetches ad placement rules and can report ad request/show events. |

## Certificate Fingerprints

| Role | Type | Fingerprint | Context |
| --- | --- | --- | --- |
| Backup router TLS | SHA256 | 98151b82dcd1605f3500104e8a56735a294866917d0e0cb056a4f8bbd464f947 | Internal VS/SOFT cert on 38[.]145[.]197[.]135:2375 |
| Backup router TLS | SHA256 | 68d4874c5bd8535fc5b3f2cd75dc19dede89e3792c441d44ba51b1143e0867a1 | Public TLS cert for router[.]anyevonline[.]com |
| Nexus APK signer | SHA256 | 17d97cb33ffa9ee04a47720ed79faf2985a85f4fabcfd98ccce26524e6ce562e | VS development certificate; signs selected Nexus builds |
| OTA ZIP cert | SHA256 | 9f6e3ba0389ee113e3cd861c57a4f39771c77ddb040a209bd919e5adc55b506b | OTA otacert with hong.luo@videostrong.com identity |
| Yoka app signer | SHA256 | f90a646f51f4b9a96694ccad099b20e97a1556c81c4fa3375dd6c42e8198231f | hong.luo@videostrong.com; Yoka, CPE and debug-tools apps |

## Network Observables

| Artifact / Component | Type | IOC | Context |
| --- | --- | --- | --- |
| ADMOYU | URL | hxxps://api[.]dgjm[.]online/lib?pageNumber=1&pageSize=10000&status=1 | Plugin listing endpoint in Nexus code |
| ADMOYU | URL | hxxps://api[.]dgjm[.]online/analysis/init | Analytics registration in Nexus code |
| Airship PCDN | Host:port | 121[.]4[.]8[.]146:22345 | Hardcoded Overseer controller in extracted Airship agent. |
| Airship PCDN | Host:port | vbox-airship-server[.]painet[.]work:22345 | Named Overseer controller in extracted Airship agent. |
| Airship PCDN | Domain | gitlab[.]paigod[.]work | Referenced server-pool source for Airship agent. |
| Airship PCDN | URL | hxxps://nat-dev[.]titannet[.]io/nat-type | Native Airship NAT checker endpoint. |
| android-grass_v1.0.0_20250411_1222.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/android-grass_v1.0.0_20250411_1222.apk | Downloads GetGrass module |
| android-grass_v1.0.0_20250417_1047.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/android-grass_v1.0.0_20250417_1047.apk | Downloads GetGrass module |
| android-grass_v1.0.1_20250422_1819.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/android-grass_v1.0.1_20250422_1819.apk | Downloads GetGrass module |
| android-grass_v1.0.2_20250429_1858.apk | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/android-grass_v1.0.2_20250429_1858.apk | Downloads GetGrass module |
| Appsalt / Honeygain proxy SDK | URL | hxxps://connect[.]sdk[.]absolut[.]fit/ws/v2 | Proxy SDK controller in Nexus and operator carrier APKs. |
| Appsalt / Honeygain relay pool | Domain | creapslpinut[.]com | Static relay candidate embedded in Appsalt / Honeygain SDK. |
| Appsalt / Honeygain relay pool | Domain | gapslpinch[.]com | Static relay candidate embedded in Appsalt / Honeygain SDK. |
| Appsalt / Honeygain relay pool | Domain | grasplpond[.]com | Static relay candidate embedded in Appsalt / Honeygain SDK. |
| Appsalt / Honeygain relay pool | Domain | clapslport[.]com | Static relay candidate embedded in Appsalt / Honeygain SDK. |
| Appsalt / Honeygain relay pool | Domain | scapslwshell[.]com | Static relay candidate embedded in Appsalt / Honeygain SDK. |
| Appsalt / Honeygain relay pool | Domain | trapslwsin[.]com | Static relay candidate embedded in Appsalt / Honeygain SDK. |
| Appsalt / Honeygain relay pool | Domain | froponic[.]com | Static Appsalt relay candidate in Nexus OTA 1.6.0303.rk7pro. |
| Appsalt / Honeygain relay pool | Domain | kepiron[.]com | Static Appsalt relay candidate in Nexus OTA 1.6.0303.rk7pro. |
| Appsalt / Honeygain relay pool | Domain | rawsindrel[.]com | Static Appsalt relay candidate in Nexus OTA 1.6.0303.rk7pro. |
| Appsalt / Honeygain relay pool | Domain | sepothael[.]com | Static Appsalt relay candidate in Nexus OTA 1.6.0303.rk7pro. |
| Appsalt / Honeygain relay pool | Domain | trapiscol[.]com | Static Appsalt relay candidate in Nexus OTA 1.6.0303.rk7pro. |
| Appsalt / Honeygain relay pool | Domain | vewsraith[.]com | Static Appsalt relay candidate in Nexus OTA 1.6.0303.rk7pro. |
| APSolo Proxy SDK | Host:port | bmw[.]bestipip[.]com:16000 | Proxy relay in Nexus code; provider per analyst attribution |
| atv-1.7.4-original-signed.apk archive | URL | hxxps://raw[.]githubusercontent[.]com/Aviciiii/ott/b578321e8d955bc198af734b812bfdc0dab48421/updates/config_package_V20251125.01.tar.gz | Downloads historical Nexus installer bundle |
| Backup router | Host:port | router[.]anyevonline[.]com:2375 | VS/SOFT internal TLS certificate on backup host |
| Bird / AMH SDK | URL | hxxp://img[.]amhib[.]com/imp.php | Bird/AMH controller decoded from Nexus 1.7.75 (SDK account 30921); also in OL loader. |
| Debugtools | IP | 23[.]94[.]49[.]57 | Some sort of developer tool. /shrug |
| DeviceThread | Domain | dt-dev-ota-server[.]devicethread[.]com | SmartThroughput development telemetry endpoint. |
| EcoSaverDaemon-1.0.2 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/appstore/EcoSaverDaemon-1.0.2-release.apk | Downloads EcoSaver daemon |
| Firmware CPE | Domain | mcstb[.]anyevonline[.]com | MECOOL-specific OEM bootstrap host; leads to task and Nexus layer. |
| FreeTV_3.11.0 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/FreeTV_3.11.0_338.xapk | Downloads FreeTV streaming app |
| Gaganode SDK | URL | hxxps://api[.]package[.]coreservice[.]io:10443/api/version/ | Gaganode version API embedded in Nexus 1.4.6 and 1.7.4. |
| Gaganode SDK | Domain | gtxvdqvuweqs[.]com | Gaganode SDK host embedded in Nexus 1.4.6 and 1.7.4. |
| Gaganode SDK | URL | hxxp://tech[.]yytsiy[.]com:9901/box/sdkheart | Gaganode heartbeat URL embedded in Nexus 1.7.4. |
| GetGrass | URL | hxxps://director[.]getgrass[.]io/checkin | Active Grass proxy director check-in |
| Jaguar | URL | hxxps://app[.]allcloud9[.]com/download/jaguar_mb002/jaguar-mb002.jar | Downloads Jaguar proxy JAR (historical procedure) |
| Jaguar | Host:port | mb002[.]jaguar-distributor[.]syslogcollector[.]com:12000 | Jaguar cleartext bootstrap controller |
| kto-7.0.7.3.xapk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/kto.xapk | Downloads KTO streaming app |
| LB102 | Domain | api[.]pixelpioneerss[.]com | Nexus LB102 dynamic-loader bootstrap |
| LB102 | Domain | bur[.]thedynamicleap[.]com | Nexus LB102 device telemetry |
| LinkFog current | URL | hxxps://webnest[.]linkfog[.]cn/downloadServerElf/organization_select | Agent organization and payload selection API. |
| LinkFog current | Host:port | newdcs[.]bkdomain[.]cn:9992 | Agent deployment channel; provider infrastructure. |
| LinkFog current | Host:port | newdcs[.]bkdomain[.]cn:9994 | Alternate agent deployment channel. |
| LinkFog current | URL | hxxps://openapi[.]bkdomain[.]cn/openapi/download/bizDeployCallback | Business payload deployment callback. |
| LinkFog current | Host:port | newstun[.]linkfog[.]cn:3478 | STUN server for LinkFog relay traversal. |
| LinkFog legacy | Domain | api[.]smrtai[.]cc | Fallback controller embedded in older LinkFog native agent. |
| LinkFog legacy | Domain | api[.]dddlink[.]link | Fallback controller embedded in older LinkFog native agent. |
| LinkFog legacy | Domain | api[.]cloudbrokerapi[.]xyz | Fallback controller embedded in older LinkFog native agent. |
| LinkFog legacy | IP | 47[.]252[.]2[.]77 | Fallback controller embedded in older LinkFog native agent. |
| lw_android_agent_special_ndk_32 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/cpe_ext_lib/lw_android_agent_special_ndk_32 | Downloads LinkFog proxy agent |
| lw_android_agent_special_ndk_32_20250717 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/cpe_ext_lib/lw_android_agent_special_ndk_32_20250717 | Downloads LinkFog proxy agent |
| lw_android_agent_special_ndk_64 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/cpe_ext_lib/lw_android_agent_special_ndk_64 | Downloads LinkFog proxy agent |
| MboxLauncher_v2.8.2_x3_pulse.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/MboxLauncher_v2.8.2_x3_pulse.apk | Downloads Mbox launcher |
| MboxLauncher_v2.8.3_x3_pulse.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/MboxLauncher_v2.8.3_x3_pulse.apk | Downloads Mbox launcher |
| Moyu / Spirit | URL | hxxps://api[.]dgjm[.]online/lib?pageNumber=1&pageSize=10000&status=1&channel=sp003 | Nexus Moyu channel-specific plugin catalog |
| mysplayer-2.1.1.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/media.player.mysplayer-v2.1.1.apk | Downloads TV media player |
| nat-checker-test.apk | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/nat-checker.apk | Downloads NAT checker |
| nat-checker-v1.2 | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/nat_checker_app.apk | Downloads NAT checker |
| Nexus 1.7.75 embedded SDK | URL | hxxps://dd[.]amazonlss[.]com/app | Static endpoint in com.android.init.android; runtime use unverified. |
| Nexus 1.7.75 embedded SDK | URL | hxxps://x[.]xxyltd[.]com/app | Static endpoint in com.android.init.android; runtime use unverified. |
| Nexus controller | IP | 219[.]134[.]163[.]210 | Primary OTT peer |
| Nexus controller | IP | 219[.]134[.]163[.]211 | Primary OTT peer |
| Nexus controller | URL | hxxps://ott[.]szbboys[.]com | Primary policy/report API |
| Nexus controller | URL | hxxp://ott[.]szbboys[.]com:8000 | Current policy backup |
| Nexus controller | IP | 38[.]145[.]197[.]135 | Backup API host |
| Nexus controller | URL | hxxp://lib[.]anyevonline[.]com:8000 | Historical policy backup; current API mirror |
| Nexus controller | URL | hxxps://extlib[.]anyevonline[.]com | Hardcoded legacy fallback; DNS unresolved at last check |
| Nexus geo pool | Domain | pool1[.]anyevonline[.]com | Primary Americas geo pool listed in client configuration. |
| Nexus geo pool | Domain | pool1-b[.]anyevonline[.]com | Backup Americas geo pool listed in client configuration. |
| Nexus geo pool | Domain | pool2[.]anyevonline[.]com | Primary Europe and Atlantic geo pool listed in client configuration. |
| Nexus OTA | URL pattern | hxxp://ota{ver}{model}[.]szbboys[.]com/otaupgrade/update | Model and version based OTA update URL template in client code. |
| Nexus-1.7.88.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/Nexus-1.7.88.apk | Downloads ABC Nexus backdoor |
| OEM OTA | Domain | update9088cn[.]s-itv[.]com | China regional OTA endpoint in VS OTA client. |
| OEM OTA | Domain | update9088tw[.]s-itv[.]com | Taiwan regional OTA endpoint in VS OTA client. |
| OEM OTA | Domain | www[.]china-ota[.]com | Allwinner OTA endpoint in VS OTA client. |
| OEM policy bridge | Host:port | extstb[.]anyevonline[.]com:8000 | Backup configuration bridge used by OEM Service |
| OTA Service | URL | hxxps://hiddeninplainsight[.]top/v2/api/auth/device/signup | Separate web-content task backend in 4.5 APK |
| OTA-RELEASE-VS-4_4_signed_for_pulse.apk | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/OTA-RELEASE-VS-4_4_signed_for_pulse.apk | Downloads VideoStrong OTA web-content runner |
| OTA-RELEASE-VS-4_5_signed_for_pulse.apk | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/OTA-RELEASE-VS-4_5_signed_for_pulse.apk | Downloads VideoStrong OTA web-content runner |
| OTA-RELEASE-VS-PROD-V4_1_signed_for_pulse.apk | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/OTA-RELEASE-VS-PROD-V4_1_signed_for_pulse.apk | Downloads VideoStrong OTA web-content runner |
| OTA-SERVICE-RELEASE-4-3_signed_for_pulse.apk | URL | hxxps://github[.]com/szwzy43/wzy/releases/download/v1.0/OTA-SERVICE-RELEASE-4-3_signed_for_pulse.apk | Downloads VideoStrong OTA web-content runner |
| OTA-SERVICE-VIDEO-STRONG-V1_0726_andriod_p_signed.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/OTA-SERVICE-VIDEO-STRONG-V1_0726_andriod_p_signed.1.apk | Downloads VideoStrong OTA web-content runner |
| OTA-SERVICE-VIDEO-STRONG-V1_0729_2_android_p_signed.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/OTA-SERVICE-VIDEO-STRONG-V1_0729_2_android_p_signed.apk | Downloads VideoStrong OTA web-content runner |
| OTA-SERVICE-VIDEO-STRONG-V2_0804_android_p_signed.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/OTA-SERVICE-VIDEO-STRONG-V2_0804_android_p_signed.apk | Downloads VideoStrong OTA web-content runner |
| OTA-SERVICE-VIDEO-STRONG-V2_0804_h313_q.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/OTA-SERVICE-VIDEO-STRONG-V2_0804_h313_q.apk | Downloads VideoStrong OTA web-content runner |
| OTA-SERVICE-VIDEO-STRONG-V2_android_p_signed.apk | URL | hxxps://github[.]com/Spink1984/apk/releases/download/v1/OTA-SERVICE-VIDEO-STRONG-V2_android_p_signed.apk | Downloads VideoStrong OTA web-content runner |
| OTA-VS-RELEASE-PROD-V4_signed_for_pluse.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/OTA-VS-RELEASE-PROD-V4_signed_for_pluse.apk | Downloads VideoStrong OTA web-content runner |
| OTT MQTT control | Domain | mqtt[.]szbboys[.]com | OTT control broker hostname; same primary peer cluster |
| PLU / FRP Lite | URL | hxxps://app[.]allcloud9[.]com/download/proxy/frp-lite.jar | Historical PLU procedure downloads FRP Lite JAR |
| PLU / FRP Lite | URL | hxxps://app[.]allcloud9[.]com/download/proxy/libfrpc-lite_arm.so | Historical PLU procedure downloads ARM FRP engine |
| PLU / FRP Lite | URL | hxxps://app[.]allcloud9[.]com/download/proxy/libfrpc-lite_arm64.so | Historical PLU procedure downloads ARM64 FRP engine |
| PLU / FRP Lite | URL | hxxps://p[.]allcloud9[.]com/proxy/login | Historical FRP Lite controller login |
| PLU / FRP Lite | URL | hxxps://p[.]allcloud9[.]com/proxy/getConfig | Historical FRP Lite relay configuration |
| PLU / PProxy | URL | hxxps://app[.]allcloud9[.]com/app/ | PLU control API for login, procedures and reports |
| Popanet SDK | Domain | byte-buff[.]com | Static proxy fallback embedded in Nexus 1.7.4; activation unverified. |
| Popanet SDK | Domain | house-spirit[.]com | Static proxy fallback embedded in Nexus 1.7.4; activation unverified. |
| Popanet SDK | Domain | novel-layer[.]com | Static proxy fallback embedded in Nexus 1.7.4; activation unverified. |
| Popanet SDK | Domain | star-layer[.]com | Static proxy fallback embedded in Nexus 1.7.4; activation unverified. |
| PProxy in Grass | URL | hxxp://zhuangshi[.]pproxy[.]top/proxy | Dormant SDK default in Grass APK; no observed use |
| SmartEntertainment-v6.2.1.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/SmartEntertainment-v6.2.1.apk | Downloads DeviceThread app manager |
| SmartPrivilege-v0.0.2.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/SmartPrivilege-v0.0.2.apk | Downloads DeviceThread privileged service |
| SmartThroughput-v1.0.0.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/other/SmartThroughput-v1.0.0.apk | Downloads DeviceThread throughput utility |
| TitanNet | URL | hxxps://termux[.]titannet[.]io/api/log/push | Module log upload in Nexus code |
| TitanNet | URL | hxxps://pcdn[.]titannet[.]io/test4/termux/ | Module bootstrap package path |
| TitanNet | URL | hxxps://termux[.]titannet[.]io/api/node/tasks | Titan task API; task payloads are controller-supplied |
| TitanNet | URL | hxxps://pcdn[.]titannet[.]io/test4/termux/bootstrap-aarch64.zip | Titan ARM64 Termux bootstrap |
| TitanNet | URL | hxxps://pcdn[.]titannet[.]io/test4/termux/bootstrap-arm.zip | Titan ARM Termux bootstrap |
| TitanNet | URL | hxxps://pcdn[.]titannet[.]io/test4/termux/bootstrap-x86_64.zip | Titan x86-64 Termux bootstrap |
| TitanNet | URL | hxxps://pcdn[.]titannet[.]io/test4/termux/bootstrap-x86.zip | Titan x86 Termux bootstrap |
| TMS / OEM | Host:port | tms[.]yokatvonline[.]com:8443 | Adjacent OEM/TMS service. |
| TMS / OEM | IP | 38[.]145[.]197[.]30 | Adjacent OEM/TMS host; Nexus role unverified |
| TraffMonetizer | Domain | blnc[.]traffmonetizer[.]com | Proxy SDK controller in Nexus and carrier APKs. |
| TraffMonetizer | Domain | srv[.]traffmonetizer[.]com | Default TraffMonetizer service host in Nexus 1.7.88 full and 1.7.89. |
| UOTA updater | Host:port | appmetrices[.]uota[.]club:2095 | OEM update endpoint embedded in CPE. |
| UOTA updater | Host:port | appmetrices[.]uota[.]xyz:2095 | Alternate OEM update endpoint embedded in CPE. |
| UOTA updater | Host:port | uota[.]uota[.]xyz:2082 | Alternate OEM update endpoint embedded in CPE. |
| videoadtime_pproxy_32 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/cpe_ext_lib/videoadtime_pproxy_32 | Downloads PProxy relay |
| videoadtime_pproxy_64 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/cpe_ext_lib/videoadtime_pproxy_64 | Downloads PProxy relay |
| VideoStrong legacy | Domain | security[.]videostrong[.]com | Historical OTT-facing hostname; Nexus role unverified |
| VS Player | Host:port | vstroplayer[.]szbboys[.]com:8010 | VS Player upload endpoint in OEM configuration. |
| WhaleScreen_aosp11 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/appstore/WhaleTV_VS_ServiceScreenSaver_1.0.9_20260603_signed_aosp11.apk | Downloads Whale TV screensaver |
| WhaleScreen_aosp9 | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/appstore/WhaleTV_VS_ServiceScreenSaver_release_1.0.10_1001000_20260618_signed_aosp9.apk | Downloads Whale TV screensaver |
| Yoka / V12 | Domain | config[.]intermedia-arts[.]tv | V12 configuration host in OEM app profiles. |
| Yoka / V12 | Domain | feedback[.]intermedia-arts[.]tv | V12 feedback and telemetry host in OEM app profiles. |
| Yoka / VS Player | Domain | config[.]sunvsg[.]com | VS Player QR configuration host; unresolved at last check. |
| Yoka app services | Domain | config[.]yokatvonline[.]com | YokaTV app configuration and content API. |
| Yoka app services | Host:port | yokaplayer[.]yokatvonline[.]com:8010 | Yoka Player upload endpoint in OEM configuration. |
| Yoka app services | Host:port | usermanual[.]yokatvonline[.]com:8010 | YokaTV user manual host in OEM configuration. |
| Yoka app store | Host:port | appstore[.]yokatvonline[.]com:8010 | Privileged app distribution backend |
| Yoka TMS | Domain | www[.]tms[.]yokatvonline[.]com | Yoka telecom management dashboard hostname. |
| YokaTVScreen-release-.develop_adshow_uka.-PLATFORM._v1.8.3 | URL | hxxps://github[.]com/ktpeng2026/ott_release/releases/download/rv1/YokaTVScreen-release-.develop_adshow_uka.-PLATFORM._v1.8.3_20260911_1034.apk | Downloads YokaTV ad screensaver |
| YokaTVScreen-release-[develop_adshow]-PLATFORM[]_v1.7.6_20260814_1402.apk | URL | hxxps://github[.]com/Aviciiii/ott/releases/download/appstore/YokaTVScreen-release-.develop_adshow.-PLATFORM._v1.7.6_20260814_1402.apk | Downloads YokaTV ad screensaver |

## SDK Identifiers

Observed SDK identifiers used in device monetization.

| SDK | Identifier |
| --- | --- |
| Appsalt / Honeygain | 16418038f955f2a1c8d99d6d2efbf81b |
| Appsalt / Honeygain | dcb48509badee499379fa1f65a2cefe5 |
| GetGrass | 011655a0-5d06-4b43-8cc3-0dd659406a18 |
| Gaganode | babpmhzezrbjazzfd61e1e388f63a9f8 |

