# GhostSocks: From Initial Access to Residential Proxy

[Referencing Research](https://synthient.com/blog/ghostsocks-from-initial-access-to-residential-proxy)

## Network Observables

| IP Address         | ASN      | Hosting Provider                  | Country | Description                  |
|--------------------|----------|-----------------------------------|---------|------------------------------|
| 46[.]8[.]232[.]106 | AS56971  | cloudbackbone.net                 | HK      | Relay Server                 |
| 46[.]8[.]236[.]61  | AS56971  | cloudbackbone.net                 | HK      | Relay Server                 |
| 91[.]212[.]166[.]91| AS198953 | proton66.ru                       | RU      | Relay Server                 |
| 91[.]212[.]166[.]9 | AS198953 | proton66.ru                       | RU      | Relay Server                 |
| 147[.]45[.]196[.]157| AS216127| nuxt.cloud                        | UK      | Relay Server                 |
| 91[.]142[.]74[.]33 | AS48282  | Hosting technology LTD            | RU      | C2 Dashboard                 |
| 86[.]54[.]24[.]25  | AS208885 | Noyobzoda Faridduni Saidilhom     | LT      | Serving GhostSocks binary    |

---

## File Observables

| Filename                               | SHA-256 Hash                                                           | Description                                  |
|----------------------------------------|------------------------------------------------------------------------|----------------------------------------------|
| %TEMP%\config                          | N/A                                                                    | Configuration file that stores relay server information |
| rcpncnel.exe                           | cda5f18be615ad27e0477c6d249d245d368ac1de81ee48239a3e39814345c04d       | GhostSocks Binary                            |
| Renewable.exe                          | f52fa1b8be929a42aafab8f0a80932e52b949ee35498f22b6d58e5e6ed107b99       | GhostSocks Binary                            |
| ByteWaveIntelligridSparkLinkMesh.exe   | f52fa1b8be929a42aafab8f0a80932e52b949ee35498f22b6d58e5e6ed107b99       | GhostSocks Binary                            |
| N/A                                    | b4709cfb8f9cf0eaabe16ab218d60a0e64c3fa568d42fcac51f867e1d2cdc1fe       | GhostSocks Binary                            |

---

## Yara Rules

```yara
rule GhostSocks_m {
	meta:
		author = "Synthient Research"
		description = "GhostSocks Binary Functions"
		version = "1.0"
		date = "2025-9-27"
		hash = "cda5f18be615ad27e0477c6d249d245d368ac1de81ee48239a3e39814345c04d"
	strings:
		$m1 = "GetAvailableRelayServer"
		$m2 = "ConnectForSocks"
		$m3 = "DynamicCredentials"
	condition:
		any of them
}
```

```yara
rule GhostSocks_s {
	meta:
		author = "Synthient Research"
		description = "GhostSocks Binary Strings"
		version = "1.0"
		date = "2025-9-27"
		hash = "cda5f18be615ad27e0477c6d249d245d368ac1de81ee48239a3e39814345c04d"
	strings:
		$s1 = "updatekilled"
		$s2 = "userId"
		$s3 = "config"
		$s4 = "socks5"
		$s5 = "%s=%s"
	condition:
		all of them
}

```
