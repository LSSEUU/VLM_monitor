"""Privacy-enforcing media storage port."""

from typing import Protocol

from labcourt.contracts.evidence import Crop, CropRequest
from labcourt.contracts.manifests import SoftwareComponentManifest
from labcourt.contracts.storage import ArtifactVerification


class FrameStore(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def software_component(self) -> SoftwareComponentManifest: ...

    def create_crop(self, request: CropRequest) -> Crop: ...

    def verify_crop(self, crop: Crop) -> ArtifactVerification: ...
