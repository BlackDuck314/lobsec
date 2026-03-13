"""
pandera schema for DXB airport passengers data validation (NORM-04).

DXB data comes from PDF files, so we validate the file exists and is readable.
"""

import os


def validate_dxb_pdf(file_path: str) -> None:
    """
    Validate DXB PDF file exists and is readable.

    Args:
        file_path: Path to PDF file

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(file_path, str):
        raise ValueError("file_path must be a string")

    if not os.path.exists(file_path):
        raise ValueError(f"PDF file does not exist: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    if not file_path.lower().endswith('.pdf'):
        raise ValueError(f"File is not a PDF: {file_path}")

    # Check file is readable
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            if header != b'%PDF':
                raise ValueError(f"File is not a valid PDF: {file_path}")
    except IOError as e:
        raise ValueError(f"Cannot read PDF file: {e}")
