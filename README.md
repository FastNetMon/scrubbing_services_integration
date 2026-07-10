# scrubbing_services_integration #

This tools offers integration of FastNetMon with different scrubbing providers

## How to get list of Profile Templates for GCore? ##

```bash
echo '{"action":"ban", "ip":"1.2.3.4"}' | LIST_PROFILE_TEMPLATES=1 bin/scrubbing_services_integration
```

## How to get list of protected networks for GCore? ##

```bash
echo '{"action":"ban", "ip":"1.2.3.4"}' | LIST_GCORE_NETWORKS=1 bin/scrubbing_services_integration
```

It needs to be built manually and then uploaded to bucket
