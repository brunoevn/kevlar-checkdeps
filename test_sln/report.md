# Dependency Status Report

Generated on 2026-07-01 23:09:30

## Summary

- **Total Checked**: 2
- **Up-to-date**: 0
- **Outdated**: 2 (Patch: 0, Minor: 1, Major: 1)
- **Security Vulnerabilities**: 1 found in 1 packages

## Dependency Details

| Package | Type | Declared | Installed | Latest | Status | Vuls | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Microsoft.CSharp` | Direct | `4.3.0` | `4.3.0` | `4.7.0` | ⚠️ Minor Update | ✅ |  |
| `Newtonsoft.Json` | Direct | `12.0.1` | `12.0.1` | `13.0.4` | ❌ Major Update | ⚠️ **1** |  |

## Security Vulnerabilities Details

### `Newtonsoft.Json@12.0.1` (1 vulnerabilities)

- **GHSA-5crp-9r3c-p9vr** [CVSS CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H]: Improper Handling of Exceptional Conditions in Newtonsoft.Json
  > Newtonsoft.Json prior to version 13.0.1 is vulnerable to Insecure Defaults due to improper handling of expressions with high nesting level that lead to StackOverFlow exception or high CPU and RAM usage. Exploiting this vulnerability results in Denial Of Service (DoS). 
> 
> The serialization and deserialization path have different properties regarding the issue.
> 
> Deserializing methods (like `JsonConvert.DeserializeObject`) will process the input that results in burning the CPU, allocating memory, and consuming a thread of execution. Quite high nesting level (>10kk, or 9.5MB of `{a:{a:{...` input) is needed to achieve the latency over 10 seconds, depending on the hardware.
> 
> Serializing methods (like `JsonConvert.Serialize` or `JObject.ToString`) will throw StackOverFlow exception with the nesting level of around 20k.
> 
> To mitigate the issue one either need to update Newtonsoft.Json to 13.0.1 or set `MaxDepth` parameter in the `JsonSerializerSettings`. This can be done globally with the following statement. After that the parsing of the nested input will fail fast with `Newtonsoft.Json.JsonReaderException`:
> 
> ``` 
> JsonConvert.DefaultSettings = () => new JsonSerializerSettings { MaxDepth = 128 };
> ```
> 
> Repro code:
> ```
> //Create a string representation of an highly nested object (JSON serialized)
> int nRep = 25000;
> string json = string.Concat(Enumerable.Repeat("{a:", nRep)) + "1" +
>  string.Concat(Enumerable.Repeat("}", nRep));
> 
> //Parse this object (leads to high CPU/RAM consumption)
> var parsedJson = JsonConvert.DeserializeObject(json);
> 
> // Methods below all throw stack overflow with nRep around 20k and higher
> // string a = parsedJson.ToString();
> // string b = JsonConvert.SerializeObject(parsedJson);
> ```
> 
> ### Additional affected product and version information
> **The original statement about the problem only affecting IIS applications is misleading.** Any application is affected, however the IIS has a behavior that stops restarting the instance after some time resulting in a harder-to-fix DoS.**

