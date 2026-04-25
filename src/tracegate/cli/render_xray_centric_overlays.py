from __future__ import annotations

from tracegate.services.xray_centric import XrayCentricOverlayRenderContext, render_xray_centric_private_overlays


def main() -> None:
    ctx = XrayCentricOverlayRenderContext.from_environ()
    render_xray_centric_private_overlays(ctx)
    print(f"xray-centric overlays written to {ctx.overlay_root}")


if __name__ == "__main__":
    main()
