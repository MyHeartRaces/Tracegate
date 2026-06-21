from __future__ import annotations

from tracegate.services.materialized_bundles import MaterializedBundleRenderContext, render_materialized_bundles


def main() -> None:
    ctx = MaterializedBundleRenderContext.from_environ()
    render_materialized_bundles(ctx)
    print(f"materialized bundles written to {ctx.materialized_root}")


if __name__ == "__main__":
    main()
