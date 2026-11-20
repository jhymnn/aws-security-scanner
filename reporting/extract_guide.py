import re
import fitz
from pathlib import Path


PDF_PATH = "data/guide.pdf"
OUTPUT_DIR = "outputs/extracted_guide_sections"


SECTION_HEADING_PATTERN = re.compile(r"^\s*(\d+\.\d+)\s+(.+?)\s*$")
TOC_LEADER_PATTERN = re.compile(r"(?:\.{3,}|…{2,}|·{5,})")


def extract_pages_text():
    doc = fitz.open(PDF_PATH)

    pages = []

    for page_num, page in enumerate(doc, start=1):
        text = page.get_text()
        pages.append({
            "page": page_num,
            "text": text
        })

    return pages


def make_full_text_with_page_markers(pages):
    parts = []

    for page in pages:
        parts.append(f"\n\n===== PAGE {page['page']} =====\n")
        parts.append(page["text"])

    return "\n".join(parts)


def find_section_positions(full_text):
    """Discover numbered section headings from the PDF text itself.

    The PDF table of contents uses dotted leaders, so ignore those lines and
    use the numbered headings in the body. This keeps the section list from
    going stale when the guide gains or changes sections.
    """
    positions_by_id = {}
    offset = 0

    for line in full_text.splitlines(keepends=True):
        stripped_line = line.strip()
        match = SECTION_HEADING_PATTERN.match(stripped_line)

        if match:
            section_id, title = match.groups()
            title = title.strip()

            if title and not TOC_LEADER_PATTERN.search(title):
                if section_id not in positions_by_id:
                    positions_by_id[section_id] = {
                        "section_id": section_id,
                        "title_keyword": title,
                        "start": offset + line.index(stripped_line),
                    }

        offset += len(line)

    positions = sorted(positions_by_id.values(), key=lambda item: item["start"])

    if not positions:
        raise ValueError(
            "PDF 본문에서 번호가 있는 섹션 제목을 찾지 못했습니다. "
            "PDF의 텍스트 레이어와 제목 형식을 확인하세요."
        )

    return positions


def split_sections(full_text, positions):
    sections = []

    for idx, pos in enumerate(positions):
        start = pos["start"]

        if idx + 1 < len(positions):
            end = positions[idx + 1]["start"]
        else:
            end = len(full_text)

        section_text = full_text[start:end].strip()

        sections.append({
            "section_id": pos["section_id"],
            "title_keyword": pos["title_keyword"],
            "text": section_text
        })

    return sections


def save_sections(sections):
    output_dir = Path(OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    for section in sections:
        section_id = section["section_id"]
        safe_id = section_id.replace(".", "_")

        output_path = output_dir / f"{safe_id}.txt"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(section["text"])

        print(f"저장 완료: {output_path}")


def main():
    pages = extract_pages_text()
    full_text = make_full_text_with_page_markers(pages)

    Path("outputs").mkdir(exist_ok=True)

    with open("outputs/sk_guide_full_text.txt", "w", encoding="utf-8") as f:
        f.write(full_text)

    positions = find_section_positions(full_text)
    sections = split_sections(full_text, positions)
    save_sections(sections)

    print(f"전체 {len(sections)}개 섹션 추출 완료")


if __name__ == "__main__":
    main()
