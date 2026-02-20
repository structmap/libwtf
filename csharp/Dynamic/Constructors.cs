using QuickConstructor.Attributes;

namespace Structmap.WebTransportFast.Dynamic;

[QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct wtf_buffer_t;
[QuickConstructor(Fields=IncludeFields.AllFields)]
public partial struct wtf_certificate_config_t
{
    [QuickConstructor(Fields=IncludeFields.AllFields)]
    public partial struct _cert_data_e__Union
    {
        [QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct _file_e__Struct;
        [QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct _protected_file_e__Struct;
        [QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct _hash_e__Struct;
        [QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct _hash_store_e__Struct;
        [QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct _pkcs12_e__Struct;
    }
};
[QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct wtf_server_config_t;
[QuickConstructor(Fields=IncludeFields.AllFields)] public partial struct wtf_context_config_t;
[QuickConstructor(Fields = IncludeFields.AllFields)] public partial struct wtf_version_info_t;
