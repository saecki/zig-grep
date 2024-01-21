import sys
import os
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.ticker import FuncFormatter
import seaborn as sns

# font_dirs = os.path.join(Path.home(), ".local/share/fonts")
# font_files = font_manager.findSystemFonts(fontpaths=font_dirs)
# for font_file in font_files:
#     font_manager.fontManager.addfont(font_file)
#
# print(plt.rcParams["font.sans-serif"][0])
# print(plt.rcParams["font.monospace"][0])

def add_ms_suffix(value, _):
    return f'{round(value)}ms'

def generate_dark_bar_chart(data, labels):
    text_color = '#c0c0b0'
    sns.set(style="darkgrid", rc={
        'figure.facecolor':'#202020',
        "axes.facecolor": "#323232",
        "grid.color": "#404040",
        "xtick.color": text_color,
        "ytick.color": text_color,
        "font.family":"JetbrainsMono Nerd Font",
    })
    
    bar_width = 0.35
    index = range(len(labels))

    fig, ax = plt.subplots()
    fig.patch.set_alpha(0)
    bar1 = ax.bar(
        index,
        data['ripgrep'],
        bar_width,
        label='ripgrep',
        color='#fcca79',
        linewidth=0
    )
    bar2 = ax.bar(
        [i + bar_width for i in index],
        data['searcher'],
        bar_width,
        label='searcher',
        color='#f7a43d',
        linewidth=0
    )
    
    ax.yaxis.set_major_formatter(FuncFormatter(add_ms_suffix))
    ax.tick_params(axis='y', labelsize=16)
    ax.set_xticks([i + bar_width / 2 for i in index])
    ax.set_xticklabels(labels, fontsize=16, fontweight='bold', color=text_color, rotation=45, ha="right")
    ax.legend(loc='upper left', labelcolor=text_color)

    plt.tight_layout()
    sns.despine(left=True, bottom=True)
    plt.show()

# Read the CSV file
df = pd.read_csv(sys.argv[1], sep='\s+', index_col=0)

# Generate the dark-themed bar chart with non-overlapping bars
generate_dark_bar_chart(df, df.index)
