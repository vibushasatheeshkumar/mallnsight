import pefile
import os
from datetime import datetime


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)

        info = {}

        # Architecture
        machine = pe.FILE_HEADER.Machine

        architectures = {
            0x14c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x1c0: "ARM",
            0xaa64: "ARM64"
        }

        info["architecture"] = architectures.get(
            machine,
            hex(machine)
        )

        # Compile Time
        info["compile_time"] = datetime.utcfromtimestamp(
            pe.FILE_HEADER.TimeDateStamp
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Entry Point
        info["entry_point"] = hex(
            pe.OPTIONAL_HEADER.AddressOfEntryPoint
        )

        # Image Base
        info["image_base"] = hex(
            pe.OPTIONAL_HEADER.ImageBase
        )

        # Number of Sections
        info["number_of_sections"] = pe.FILE_HEADER.NumberOfSections

        # Section Names
        sections = []

        for section in pe.sections:
            sections.append({
                "name": section.Name.decode(errors="ignore").strip("\x00"),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 2)
            })

        info["sections"] = sections

        # Imports
        imports = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")

                for imp in entry.imports:
                    imports.append({
                        "dll": dll,
                        "function": (
                            imp.name.decode(errors="ignore")
                            if imp.name
                            else f"Ordinal {imp.ordinal}"
                        )
                    })

        info["imports"] = imports

        # Exports
        exports = []

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(
                    exp.name.decode(errors="ignore")
                    if exp.name
                    else f"Ordinal {exp.ordinal}"
                )

        info["exports"] = exports

        return info

    except Exception as e:
        return {
            "error": str(e)
        }