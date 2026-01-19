"""JAR file string extractor using JVM bytecode constant pool parsing.

This module extracts hardcoded strings from .jar files by:
1. Parsing the constant pool of .class files (JVM bytecode layer)
2. Extracting CONSTANT_Utf8 entries that are referenced by CONSTANT_String
3. Optionally using CFR/FernFlower for context information

This approach extracts strings from the ground truth (bytecode), not from
decompiled text which may have inaccuracies.

JVM Class File Format Reference:
    - https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html

Note on tools:
    - jadx: For Android DEX files, NOT optimal for JVM JAR
    - CFR/FernFlower: For JVM bytecode decompilation (optional, for context only)
"""

import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import zipfile

from log import logger


# JVM Constant Pool Tag Values (from JVM spec)
CONSTANT_Utf8 = 1
CONSTANT_Integer = 3
CONSTANT_Float = 4
CONSTANT_Long = 5
CONSTANT_Double = 6
CONSTANT_Class = 7
CONSTANT_String = 8
CONSTANT_Fieldref = 9
CONSTANT_Methodref = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_NameAndType = 12
CONSTANT_MethodHandle = 15
CONSTANT_MethodType = 16
CONSTANT_Dynamic = 17
CONSTANT_InvokeDynamic = 18
CONSTANT_Module = 19
CONSTANT_Package = 20


@dataclass
class ExtractedString:
    """Represents an extracted string from Java bytecode."""
    value: str
    file: str           # Relative path within JAR (e.g., com/example/Foo.class)
    class_name: str     # Fully qualified class name (e.g., com.example.Foo)
    line: int           # Line number (0 if from bytecode, >0 if from decompiled source)
    context: str        # Context info or empty
    length: int
    source: str = "constant_pool"  # "constant_pool" or "decompiled"


class ClassFileParser:
    """Parser for JVM .class file constant pool."""
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        
    def read_u1(self) -> int:
        """Read unsigned 1-byte value."""
        val = self.data[self.pos]
        self.pos += 1
        return val
    
    def read_u2(self) -> int:
        """Read unsigned 2-byte value (big-endian)."""
        val = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return val
    
    def read_u4(self) -> int:
        """Read unsigned 4-byte value (big-endian)."""
        val = struct.unpack('>I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val
    
    def read_bytes(self, n: int) -> bytes:
        """Read n bytes."""
        val = self.data[self.pos:self.pos+n]
        self.pos += n
        return val
    
    def parse_constant_pool(self) -> Tuple[List[Optional[Any]], Set[int]]:
        """Parse the constant pool and return (entries, string_indices).
        
        Returns:
            Tuple of:
            - List of constant pool entries (index 0 is unused)
            - Set of indices that are CONSTANT_String entries (pointing to Utf8)
        """
        # Verify magic number
        magic = self.read_u4()
        if magic != 0xCAFEBABE:
            raise ValueError(f"Invalid class file magic: {hex(magic)}")
        
        # Skip version info
        minor_version = self.read_u2()
        major_version = self.read_u2()
        
        # Read constant pool count
        cp_count = self.read_u2()
        
        # Constant pool entries (1-indexed, entry 0 is unused)
        entries: List[Optional[Any]] = [None] * cp_count
        string_indices: Set[int] = set()  # Indices of Utf8 entries referenced by CONSTANT_String
        
        i = 1
        while i < cp_count:
            tag = self.read_u1()
            
            if tag == CONSTANT_Utf8:
                length = self.read_u2()
                utf8_bytes = self.read_bytes(length)
                try:
                    entries[i] = utf8_bytes.decode('utf-8', errors='replace')
                except:
                    entries[i] = utf8_bytes.decode('latin-1', errors='replace')
                    
            elif tag == CONSTANT_Integer:
                self.read_u4()
                entries[i] = ('int',)
                
            elif tag == CONSTANT_Float:
                self.read_u4()
                entries[i] = ('float',)
                
            elif tag == CONSTANT_Long:
                self.read_u4()
                self.read_u4()
                entries[i] = ('long',)
                i += 1  # Long takes 2 slots
                
            elif tag == CONSTANT_Double:
                self.read_u4()
                self.read_u4()
                entries[i] = ('double',)
                i += 1  # Double takes 2 slots
                
            elif tag == CONSTANT_Class:
                name_index = self.read_u2()
                entries[i] = ('class', name_index)
                
            elif tag == CONSTANT_String:
                string_index = self.read_u2()
                entries[i] = ('string', string_index)
                string_indices.add(string_index)  # Mark this Utf8 as a real string
                
            elif tag == CONSTANT_Fieldref:
                self.read_u2()
                self.read_u2()
                entries[i] = ('fieldref',)
                
            elif tag == CONSTANT_Methodref:
                self.read_u2()
                self.read_u2()
                entries[i] = ('methodref',)
                
            elif tag == CONSTANT_InterfaceMethodref:
                self.read_u2()
                self.read_u2()
                entries[i] = ('interfacemethodref',)
                
            elif tag == CONSTANT_NameAndType:
                self.read_u2()
                self.read_u2()
                entries[i] = ('nameandtype',)
                
            elif tag == CONSTANT_MethodHandle:
                self.read_u1()
                self.read_u2()
                entries[i] = ('methodhandle',)
                
            elif tag == CONSTANT_MethodType:
                self.read_u2()
                entries[i] = ('methodtype',)
                
            elif tag == CONSTANT_Dynamic:
                self.read_u2()
                self.read_u2()
                entries[i] = ('dynamic',)
                
            elif tag == CONSTANT_InvokeDynamic:
                self.read_u2()
                self.read_u2()
                entries[i] = ('invokedynamic',)
                
            elif tag == CONSTANT_Module:
                self.read_u2()
                entries[i] = ('module',)
                
            elif tag == CONSTANT_Package:
                self.read_u2()
                entries[i] = ('package',)
                
            else:
                raise ValueError(f"Unknown constant pool tag: {tag} at index {i}")
            
            i += 1
        
        return entries, string_indices


class JarStringExtractor:
    """Extract hardcoded strings from JAR files using bytecode parsing."""

    # Minimum string length to include
    MIN_STRING_LENGTH = 4
    
    # Strings to exclude (common noise)
    EXCLUDE_PATTERNS = [
        r'^[a-zA-Z]$',                    # Single letters
        r'^\d+$',                          # Pure numbers
        r'^[{}\[\](),;:.<>]+$',           # Pure punctuation
        r'^(true|false|null)$',           # Java literals
        r'^(I|V|Z|B|C|S|J|F|D|L.*;|\[+[IVZBCSJFDL])$',  # JVM type descriptors
        r'^\(\)?[IVZBCSJFDL\[;]*$',       # Method descriptors
        r'^<init>$|^<clinit>$',           # Constructor/static init
        r'^(Code|LineNumberTable|LocalVariableTable|StackMapTable)$',  # Attributes
        r'^(SourceFile|InnerClasses|EnclosingMethod|Signature)$',
        r'^(Deprecated|RuntimeVisibleAnnotations|RuntimeInvisibleAnnotations)$',
        r'^(AnnotationDefault|BootstrapMethods|NestHost|NestMembers)$',
        r'^java/lang/|^java/util/|^java/io/',  # Standard library refs
    ]

    def __init__(self, cfr_path: str = "cfr"):
        """Initialize extractor.
        
        Args:
            cfr_path: Path to CFR decompiler (optional, for context).
        """
        self.cfr_path = cfr_path
        self._exclude_compiled = [re.compile(p) for p in self.EXCLUDE_PATTERNS]

    def check_cfr(self) -> bool:
        """Check if CFR decompiler is available."""
        try:
            # CFR is typically a .jar file, check common locations
            cfr_jar = self._find_cfr_jar()
            return cfr_jar is not None
        except Exception:
            return False
    
    def _find_cfr_jar(self) -> Optional[str]:
        """Find CFR jar file."""
        # Common locations
        search_paths = [
            Path.home() / ".local" / "share" / "cfr" / "cfr.jar",
            Path("/usr/share/java/cfr.jar"),
            Path("/opt/cfr/cfr.jar"),
        ]
        for p in search_paths:
            if p.exists():
                return str(p)
        return None

    def extract_strings(self, jar_path: str, max_strings: int = 100000) -> Dict[str, Any]:
        """Extract strings from a JAR file using bytecode constant pool parsing.
        
        Args:
            jar_path: Path to the JAR file.
            max_strings: Maximum number of strings to extract.
            
        Returns:
            Dict with keys: count, jar_file, extraction_method, strings
        """
        jar_path = Path(jar_path)
        if not jar_path.exists():
            raise FileNotFoundError(f"JAR file not found: {jar_path}")
        
        if not jar_path.suffix.lower() == '.jar':
            raise ValueError(f"Not a JAR file: {jar_path}")

        logger.info(f"[JarExtractor] Parsing bytecode constant pools from {jar_path.name}...")
        
        strings: List[ExtractedString] = []
        seen_values: Set[str] = set()
        class_count = 0
        
        try:
            with zipfile.ZipFile(jar_path, 'r') as zf:
                for name in zf.namelist():
                    if len(strings) >= max_strings:
                        break
                    if not name.endswith('.class'):
                        continue
                    
                    class_count += 1
                    class_name = name.replace('/', '.').replace('.class', '')
                    
                    try:
                        data = zf.read(name)
                        extracted = self._parse_class_strings(data, name, class_name)
                        
                        for ext_str in extracted:
                            if len(strings) >= max_strings:
                                break
                            if ext_str.value.lower() in seen_values:
                                continue
                            
                            seen_values.add(ext_str.value.lower())
                            strings.append(ext_str)
                            
                    except Exception as e:
                        logger.debug(f"Error parsing {name}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Failed to read JAR: {e}")
            raise

        logger.info(f"[JarExtractor] Extracted {len(strings)} strings from {class_count} classes")
        
        return {
            "count": len(strings),
            "jar_file": jar_path.name,
            "extraction_method": "bytecode_constant_pool",
            "class_count": class_count,
            "strings": [asdict(s) for s in strings]
        }

    def _parse_class_strings(self, data: bytes, file_path: str, class_name: str) -> List[ExtractedString]:
        """Parse a single .class file and extract CONSTANT_String entries."""
        result: List[ExtractedString] = []
        
        try:
            parser = ClassFileParser(data)
            entries, string_indices = parser.parse_constant_pool()
            
            # Only extract Utf8 entries that are referenced by CONSTANT_String
            # This filters out class names, method names, descriptors, etc.
            for idx in string_indices:
                if idx < len(entries) and isinstance(entries[idx], str):
                    value = entries[idx]
                    
                    # Apply filters
                    if len(value) < self.MIN_STRING_LENGTH:
                        continue
                    if self._should_exclude(value):
                        continue
                    
                    result.append(ExtractedString(
                        value=value,
                        file=file_path,
                        class_name=class_name,
                        line=0,  # Line info not available from bytecode
                        context="",
                        length=len(value),
                        source="constant_pool"
                    ))
                    
        except Exception as e:
            logger.debug(f"Failed to parse class file {file_path}: {e}")
        
        return result

    def _should_exclude(self, value: str) -> bool:
        """Check if string should be excluded."""
        for pattern in self._exclude_compiled:
            if pattern.match(value):
                return True
        return False

    def extract_strings_with_context(self, jar_path: str, max_strings: int = 100000) -> Dict[str, Any]:
        """Extract strings with decompiled context using CFR (if available).
        
        Falls back to bytecode-only extraction if CFR is not available.
        """
        # First get bytecode strings
        result = self.extract_strings(jar_path, max_strings)
        
        # Try to add context with CFR
        cfr_jar = self._find_cfr_jar()
        if cfr_jar is None:
            logger.info("[JarExtractor] CFR not found, returning bytecode-only results")
            return result
        
        # TODO: Implement CFR decompilation for context
        # For now, just return bytecode results
        return result
        

# Convenience function for standalone usage
def extract_jar_strings(jar_path: str, max_strings: int = 100000) -> Dict[str, Any]:
    """Extract strings from a JAR file.
    
    Args:
        jar_path: Path to the JAR file.
        max_strings: Maximum strings to extract.
        
    Returns:
        Dict with extraction results.
    """
    extractor = JarStringExtractor()
    return extractor.extract_strings(jar_path, max_strings)


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python jar_string_extractor.py <jar_file>")
        sys.exit(1)
    
    jar_path = sys.argv[1]
    result = extract_jar_strings(jar_path)
    print(f"Extracted {result['count']} strings from {result['jar_file']}")
    print(f"Method: {result['extraction_method']}")
    print(f"Classes parsed: {result.get('class_count', 'N/A')}")
    
    # Print first 20 strings as sample
    print("\nSample strings:")
    for s in result['strings'][:20]:
        print(f"  [{s['class_name']}] {s['value'][:100]}")
