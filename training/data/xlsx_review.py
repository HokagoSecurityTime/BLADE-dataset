"""Read review workbooks without executing formulas or modifying the originals."""
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}


def sheets(path: Path) -> dict[str, list[dict[str, str]]]:
    result = {}
    with ZipFile(path) as archive:
        strings = []
        if 'xl/sharedStrings.xml' in archive.namelist():
            strings = [''.join(n.itertext()) for n in ET.fromstring(archive.read('xl/sharedStrings.xml')).findall('m:si', NS)]
        for name in archive.namelist():
            if not name.startswith('xl/worksheets/sheet') or not name.endswith('.xml'):
                continue
            rows = []
            for row in ET.fromstring(archive.read(name)).findall('m:sheetData/m:row', NS):
                values = {}
                for cell in row:
                    value = cell.find('m:v', NS)
                    inline = cell.find('m:is', NS)
                    text = value.text if value is not None else ''
                    if cell.attrib.get('t') == 's':
                        text = strings[int(text)]
                    elif inline is not None:
                        text = ''.join(inline.itertext())
                    values[''.join(c for c in cell.attrib['r'] if c.isalpha())] = text or ''
                rows.append(values)
            result[name] = rows
    return result
