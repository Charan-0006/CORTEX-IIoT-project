import matplotlib.pyplot as plt

def setup_plotting_style(style="seaborn-v0_8-whitegrid", font_scale=1.0):
    """Set up standardized plotting style and aesthetics."""
    try:
        plt.style.use(style)
    except Exception:
        plt.style.use("default")
    plt.rcParams["font.sans-serif"] = "DejaVu Sans"
    plt.rcParams["axes.edgecolor"] = "#cccccc"
    plt.rcParams["axes.linewidth"] = 0.8

def save_publication_figure(fig, filepath, dpi=300):
    """Save figure with publication-quality resolution and layout formatting."""
    fig.tight_layout()
    fig.savefig(filepath, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
