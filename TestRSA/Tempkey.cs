using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace TestRSA
{

    public class Tempkey
    {
        [JsonProperty("KeyId")]
        public string KeyId { get; set; }

        [JsonProperty("Parameters")]
        public Parameters Parameters { get; set; }
    }

    public class Parameters
    {
        [JsonProperty("D")]
        public string D { get; set; }

        [JsonProperty("DP")]
        public string Dp { get; set; }

        [JsonProperty("DQ")]
        public string Dq { get; set; }

        [JsonProperty("Exponent")]
        public string Exponent { get; set; }

        [JsonProperty("InverseQ")]
        public string InverseQ { get; set; }

        [JsonProperty("Modulus")]
        public string Modulus { get; set; }

        [JsonProperty("P")]
        public string P { get; set; }

        [JsonProperty("Q")]
        public string Q { get; set; }
    }
}
