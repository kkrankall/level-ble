"""Brand images Home Assistant serves from custom_components/level_ble/brand/."""

from __future__ import annotations

from pathlib import Path

from homeassistant.components.brands.const import ALLOWED_IMAGES
from PIL import Image

BRAND = Path(__file__).parents[1] / "custom_components" / "level_ble" / "brand"
SIZES = {"icon.png": (256, 256), "icon@2x.png": (512, 512)}


def test_brand_images_are_allowed_and_sized() -> None:
    files = {p.name for p in BRAND.iterdir()}
    assert files == set(SIZES)
    assert files <= ALLOWED_IMAGES
    for name, size in SIZES.items():
        with Image.open(BRAND / name) as image:
            assert image.format == "PNG"
            assert image.size == size
            assert image.mode == "RGBA"
            assert image.getpixel((0, 0))[3] == 0  # transparent outside the rounded badge


async def test_home_assistant_serves_the_icon(hass, hass_client) -> None:
    from homeassistant.setup import async_setup_component

    assert await async_setup_component(hass, "brands", {})
    client = await hass_client()
    for name in SIZES:
        resp = await client.get(f"/api/brands/integration/level_ble/{name}?placeholder=no")
        assert resp.status == 200, name
        assert await resp.read() == (BRAND / name).read_bytes()
    # logo.png isn't shipped; HA falls back to the icon.
    resp = await client.get("/api/brands/integration/level_ble/logo.png?placeholder=no")
    assert await resp.read() == (BRAND / "icon.png").read_bytes()
