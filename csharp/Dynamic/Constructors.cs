using QuickConstructor.Attributes;

namespace Structmap.WebTransportFast.Dynamic;

[QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct wtf_buffer_t;
[QuickConstructor(Fields=IncludeFields.AllFields)]
public partial struct wtf_certificate_config_t
{
    public partial struct _cert_data_e__Union
    {
        public _cert_data_e__Union(_file_e__Struct fileEStruct)
        {
            file = fileEStruct;
        }
        [QuickConstructor(Fields = IncludeFields.AllFields)]
        public partial struct _file_e__Struct;
        public _cert_data_e__Union(_protected_file_e__Struct protected_file_e__Struct) {
            protected_file = protected_file_e__Struct;
        }
        [QuickConstructor(Fields = IncludeFields.AllFields)]
        public partial struct _protected_file_e__Struct;
        public _cert_data_e__Union(_hash_e__Struct hash_e__Struct) {
            hash = hash_e__Struct;
        }
        [QuickConstructor(Fields = IncludeFields.AllFields)]
        public partial struct _hash_e__Struct;
        public _cert_data_e__Union(_hash_store_e__Struct hash_store_e__Struct) {
            hash_store = hash_store_e__Struct;
        }
        [QuickConstructor(Fields = IncludeFields.AllFields)]
        public partial struct _hash_store_e__Struct;
        public _cert_data_e__Union(_pkcs12_e__Struct pkcs12_e__Struct) {
            pkcs12 = pkcs12_e__Struct;
        }
        [QuickConstructor(Fields = IncludeFields.AllFields)]
        public partial struct _pkcs12_e__Struct;
    }
};
[QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct wtf_server_config_t;
[QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct wtf_context_config_t;
[QuickConstructor(Fields = IncludeFields.AllFields)] public partial struct wtf_version_info_t;
