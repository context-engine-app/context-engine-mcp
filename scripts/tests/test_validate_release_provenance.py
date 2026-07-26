"""Public-layout smoke tests for the byte-identical portable validators."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from scripts import validate_channel_candidates
from scripts import validate_release_provenance

ReadCandidateArchive = Callable[
    [Path, Mapping[str, Mapping[str, object]], str], dict[str, bytes]
]


class PortableValidatorLayoutTests(unittest.TestCase):
    def test_public_layout_imports_both_validators(self) -> None:
        self.assertTrue(callable(validate_release_provenance.validate_staging))
        self.assertTrue(callable(validate_release_provenance.validate_public_draft))
        self.assertTrue(
            callable(validate_channel_candidates.validate_channel_candidates)
        )

    def test_validators_pin_the_canonical_schema_bytes(self) -> None:
        self.assertEqual(
            validate_release_provenance.MANIFEST_SCHEMA_SHA256,
            "b1516b5472ce1b5a50b855f9db58be8fa6e519bcff4d5878432b499482eb9a0a",
        )
        self.assertEqual(
            validate_release_provenance.PROVENANCE_SCHEMA_SHA256,
            "2a875915958bb8ed401e948fc98fbea901015a6f77a57db9c2d36e798be048c7",
        )
        self.assertEqual(
            validate_release_provenance.STAGING_SCHEMA_SHA256,
            "3b617b71f891dccaee0a7fc9c80a1da0b275b6eaf67f60fd073692e6d99cfecf",
        )
        self.assertEqual(
            validate_channel_candidates.CHANNEL_SCHEMA_SHA256,
            "7ce660193dc346c70fd0c8db57bd1d91d1743d3b6059959b96f76443d037d57a",
        )
        self.assertEqual(
            validate_channel_candidates.MANIFEST_SCHEMA_SHA256,
            "b1516b5472ce1b5a50b855f9db58be8fa6e519bcff4d5878432b499482eb9a0a",
        )

    def test_gnu_archive_without_extensions_is_rejected(self) -> None:
        member_name = "formula/context-engine.rb"
        member_data = b"candidate\n"
        output = io.BytesIO()
        with gzip.GzipFile(
            fileobj=output, mode="wb", filename="", mtime=0
        ) as gzip_stream:
            with tarfile.open(
                fileobj=gzip_stream, mode="w", format=tarfile.GNU_FORMAT
            ) as archive:
                info = tarfile.TarInfo(member_name)
                info.size = len(member_data)
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.type = tarfile.REGTYPE
                archive.addfile(info, io.BytesIO(member_data))

        archive_bytes = output.getvalue()
        records: dict[str, Mapping[str, object]] = {
            member_name: {
                "size": len(member_data),
                "sha256": hashlib.sha256(member_data).hexdigest(),
            }
        }
        read_candidate_archive = cast(
            ReadCandidateArchive,
            getattr(validate_channel_candidates, "_read_candidate_archive"),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "channel-candidates.tar.gz"
            _ = archive_path.write_bytes(archive_bytes)
            archive_path.chmod(0o644)
            with self.assertRaises(
                validate_channel_candidates.CandidateValidationError
            ):
                _ = read_candidate_archive(
                    archive_path,
                    records,
                    hashlib.sha256(archive_bytes).hexdigest(),
                )


if __name__ == "__main__":
    _ = unittest.main()
