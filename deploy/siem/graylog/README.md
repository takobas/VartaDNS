# VartaDNS → Graylog

1. **System → Inputs → Syslog UDP** (or Syslog TCP), port e.g. 1514, launch.
   Graylog parses the RFC 5424 header (time, host, application `vartadns`,
   message id `QUERY` / `AUDIT`).
2. In VartaDNS: **Settings → Syslog / SIEM** → address `graylog-ip:1514`,
   protocol UDP or TCP, mode "Threats only" (or more) → Save → "Send test event".
3. The message body is JSON. Turn it into fields with a pipeline rule
   (**System → Pipelines**), connected to the stream with the input:

```
rule "vartadns json"
when
  has_field("application_name") && to_string($message.application_name) == "vartadns"
then
  let j = parse_json(to_string($message.message));
  set_fields(to_map(j), "varta_");
end
```

   Fields then look like `varta_client`, `varta_device`, `varta_name`,
   `varta_status`, `varta_kind`, `varta_source`.

4. Useful searches / alerts:
   - `varta_kind:malware AND varta_status:blocked`
   - an Event Definition "aggregation": count() > 5 of `varta_kind:malware`
     grouped by `varta_client` within 1 hour (possible infection).

Field names of the header depend on the Graylog version and input type;
check one received message and adjust the rule if `application_name` is
named differently. This guide was not tested on a live Graylog.
