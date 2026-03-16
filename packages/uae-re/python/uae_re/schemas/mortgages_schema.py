"""
pandera schema for CBUAE mortgage statistics data validation (NORM-04).

CBUAE mortgage data comes from PDF files, so we validate the file exists and
is readable. Value-range validation is done in the normalizer after extraction.
"""

import os


def validate_mortgages_pdf(file_path: str) -> None:
    """
    Validate CBUAE mortgages PDF file exists and is readable.

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

    # Check file is a valid PDF
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            if header != b'%PDF':
                raise ValueError(f"File is not a valid PDF: {file_path}")
    except IOError as e:
        raise ValueError(f"Cannot read PDF file: {e}")


def validate_eibor_rate(rate: float) -> None:
    """
    Validate EIBOR rate is within expected range.

    EIBOR should be between 0% and 15% — outside this range indicates
    extraction error (wrong table row) rather than real rate.

    Args:
        rate: EIBOR rate as a percentage

    Raises:
        ValueError: If rate is outside expected range
    """
    if not isinstance(rate, (int, float)):
        raise ValueError(f"EIBOR rate must be a number, got: {type(rate).__name__}")

    if rate < 0 or rate > 15:
        raise ValueError(
            f"EIBOR rate {rate:.4f}% outside expected range (0-15%). "
            f"Likely incorrect table row extraction. Check PDF page targeting."
        )
