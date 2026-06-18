// Vulnerable: CSH-078
TypeNameHandling = TypeNameHandling.Auto,
              TraceWriter = traceWriter
              };
      Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson);
  }
public void SafeDeserialize(){
  Bar newBar = JsonConvert.DeserializeObject<Bar>(someJson, new JsonSerializerSettings
  {
