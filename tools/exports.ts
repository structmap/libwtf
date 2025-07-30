const path = "include/wtf.h";
const file = Bun.file(path);
const text = await file.text();

function removeComments(content: string): string {
    content = content.replace(/\/\/.*$/gm, '');
    content = content.replace(/\/\*[\s\S]*?\*\//g, '');
    return content;
}

function parseWTFApiMethods(content: string): string[] {
    const cleanContent = removeComments(content);
    const methodNames: string[] = [];
    const wtfApiRegex = /WTF_API\s+[^;]+?\s+(\w+)\s*\([^)]*\)\s*;/gs;
    let match = wtfApiRegex.exec(cleanContent);
    while (match !== null) {
        const methodName = match[1];
        methodNames.push(methodName);
        match = wtfApiRegex.exec(cleanContent);
    }
    return methodNames;
}

function createDirectories() {
    const dirs = ['cmake/export/darwin', 'cmake/export/linux', 'cmake/export/windows'];
    for (const dir of dirs) {
        try {
            Bun.spawnSync(['mkdir', '-p', dir]);
        } catch (error) {
            console.error(`Error creating directory ${dir}:`, error);
        }
    }
}

function generateDarwinExports(methods: string[]): string {
    const exports = methods.map(method => `_${method}`).join('\n');
    return `# Auto-generated Darwin export list from wtf.h
# Do not edit manually - regenerate using export script
${exports}
`;
}

function generateLinuxExports(methods: string[]): string {
    const exports = methods.join('; ');
    return `# Auto-generated Linux version script from wtf.h
# Do not edit manually - regenerate using export script
wtf
{
  global: ${exports};
  local: *;
};
`;
}

function generateWindowsDef(methods: string[]): string {
    const exports = methods.map(method => `    ${method}`).join('\n');
    return `; Auto-generated Windows module definition file from wtf.h
; Do not edit manually - regenerate using export script
LIBRARY @WTF_LIBRARY_NAME@
EXPORTS
${exports}
`;
}

function generateWindowsRC(): string {
    return `//
//    Auto-generated Windows resource file for WTF library
//    Do not edit manually - regenerate using export script
//
#include <windows.h>
#define VER_FILETYPE                VFT_DLL
#define VER_FILESUBTYPE             VFT2_UNKNOWN
#define VER_ORIGINALFILENAME_STR    "@WTF_LIBRARY_NAME@.dll"
#define VER_PRODUCTNAME_STR         "WebTransport Fast"
#define VER_COMPANYNAME_STR         "6over3 Institute"
#define VER_LEGALCOPYRIGHT_STR      "Copyright (c) 6over3 Institute"
#define VER_FILEDESCRIPTION_STR     "A fast WebTransport library"

#define VER_FILEVERSION             @WTF_VERSION_MAJOR@,@WTF_VERSION_MINOR@,@WTF_VERSION_PATCH@,0
#define VER_FILEVERSION_STR         "@WTF_VERSION_MAJOR@.@WTF_VERSION_MINOR@.@WTF_VERSION_PATCH@.0"
#define VER_PRODUCTVERSION          @WTF_VERSION_MAJOR@,@WTF_VERSION_MINOR@,@WTF_VERSION_PATCH@,0
#define VER_PRODUCTVERSION_STR      "@WTF_VERSION_MAJOR@.@WTF_VERSION_MINOR@.@WTF_VERSION_PATCH@.0"

VS_VERSION_INFO VERSIONINFO
FILEVERSION     VER_FILEVERSION
PRODUCTVERSION  VER_PRODUCTVERSION
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       0x0L
FILEOS          VOS__WINDOWS32
FILETYPE        VER_FILETYPE
FILESUBTYPE     VER_FILESUBTYPE
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      VER_COMPANYNAME_STR
            VALUE "FileDescription", VER_FILEDESCRIPTION_STR
            VALUE "FileVersion",     VER_FILEVERSION_STR
            VALUE "InternalName",    "@WTF_LIBRARY_NAME@"
            VALUE "LegalCopyright",  VER_LEGALCOPYRIGHT_STR
            VALUE "OriginalFilename", VER_ORIGINALFILENAME_STR
            VALUE "ProductName",     VER_PRODUCTNAME_STR
            VALUE "ProductVersion",  VER_PRODUCTVERSION_STR
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
`;
}

async function writeFile(filePath: string, content: string) {
    try {
        await Bun.write(filePath, content);
        console.log(`✓ Generated: ${filePath}`);
    } catch (error) {
        console.error(`✗ Error writing ${filePath}:`, error);
    }
}

// Parse the file and get all WTF_API method names
const wtfApiMethods = parseWTFApiMethods(text);
console.log("Found WTF_API methods:");
console.log(wtfApiMethods);
console.log(`\nTotal methods: ${wtfApiMethods.length}`);

// Group methods by prefix for better organization
const groupedMethods = wtfApiMethods.reduce((groups, method) => {
    const prefix = method.split('_').slice(0, 2).join('_'); // e.g., "wtf_context"
    if (!groups[prefix]) {
        groups[prefix] = [];
    }
    groups[prefix].push(method);
    return groups;
}, {} as Record<string, string[]>);

console.log("\nGrouped by prefix:");
for (const [prefix, methods] of Object.entries(groupedMethods)) {
    console.log(`${prefix}: ${methods.length} methods`);
    methods.forEach(method => console.log(`  - ${method}`));
}

// Create export directories
console.log("\nCreating export directories...");
createDirectories();

// Generate export files
console.log("\nGenerating export files...");

const darwinExports = generateDarwinExports(wtfApiMethods);
const linuxExports = generateLinuxExports(wtfApiMethods);
const windowsDef = generateWindowsDef(wtfApiMethods);
const windowsRC = generateWindowsRC();
// Write all files
await Promise.all([
    writeFile('cmake/export/darwin/exports.txt', darwinExports),
    writeFile('cmake/export/linux/exports.txt', linuxExports),
    writeFile('cmake/export/windows/wtf.def.in', windowsDef),
    writeFile('cmake/export/windows/wtf.rc.in', windowsRC),
]);

console.log("\n🎉 Export file generation complete!");
console.log("\nGenerated files:");
console.log("📁 export/");
console.log("  📁 darwin/");
console.log("    📄 exports.txt          - macOS exported symbols list");
console.log("  📁 linux/");
console.log("    📄 exports.txt          - Linux version script");
console.log("  📁 windows/");
console.log("    📄 wtf.def.in           - Windows module definition template");
console.log("    📄 wtf.rc.in            - Windows resource template");

console.log(`\nSymbol summary: ${wtfApiMethods.length} public API functions will be exported`);