import plotly.graph_objects as go

_BG = '#2C3347'   # dark slate matching the infographic style


def _fortinet_red_color(v, min_v, max_v):
    """Fortinet Red gradient: dark maroon → Fortinet Red #DA291C."""
    rng = max_v - min_v or 1
    t = (v - min_v) / rng
    r = int(120 + t * 98)   # 120 → 218
    g = int(10 + t * 31)    # 10 → 41
    b = int(5 + t * 23)     # 5 → 28
    return f'rgba({r},{g},{b},0.90)'


def render_bubbles(labels, values, title, width, height, fmt='svg', unit='count'):
    """Infographic-style circles with bold numbers inside. Sorted largest first."""
    n = len(labels)
    if n == 0:
        fig = go.Figure()
        fig.update_layout(
            plot_bgcolor=_BG, paper_bgcolor=_BG,
            title=dict(text=f'{title} — No Data',
                       font=dict(size=16, color='#FFFFFF', family='Inter, sans-serif'), x=0.5)
        )
        return fig.to_image(format=fmt, width=width, height=height)

    # Sort descending
    pairs = sorted(zip(values, labels), reverse=True)
    values_s = [p[0] for p in pairs]
    labels_s = [p[1] for p in pairs]

    # Grid layout — max 5 per row, rows centered
    cols = min(5, n)
    x_pos, y_pos = [], []
    for i in range(n):
        row, col = divmod(i, cols)
        row_n = min(cols, n - row * cols)
        x_off = (cols - row_n) / 2.0
        x_pos.append((col + x_off) * 10.0)
        y_pos.append(-row * 10.0)

    # Pixel diameters — scale with export width
    min_v, max_v = min(values_s), max(values_s)
    rng = max_v - min_v or 1
    sc = width / 1200
    min_px = int(70 * sc)
    max_px = int(160 * sc)
    px_sizes = [int(min_px + (v - min_v) / rng * (max_px - min_px)) for v in values_s]

    # Color: Fortinet Red gradient
    colors = [_fortinet_red_color(v, min_v, max_v) for v in values_s]

    # Bold number large on line 1, short label on line 2
    short = [lb[:16] + '…' if len(lb) > 16 else lb for lb in labels_s]
    num_size = max(14, int(18 * sc))
    lbl_size = max(8, int(10 * sc))
    texts = [
        f'<span style="font-size:{num_size}px"><b>{v}</b></span><br>'
        f'<span style="font-size:{lbl_size}px">{s}</span>'
        for v, s in zip(values_s, short)
    ]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x_pos, y=y_pos,
        mode='markers+text',
        marker=dict(
            size=px_sizes, sizemode='diameter',
            color=colors,
            line=dict(color='rgba(218,41,28,0.55)', width=3)
        ),
        text=texts,
        textposition='middle center',
        textfont=dict(color='white', size=max(10, int(12 * sc)), family='Inter, sans-serif'),
        customdata=list(zip(labels_s, values_s)),
        hovertemplate=f'<b>%{{customdata[0]}}</b><br>{unit}: %{{customdata[1]}}<extra></extra>',
        showlegend=False
    ))

    pad_x = 9
    pad_y = 9
    fig.update_layout(
        title=dict(text=title, font=dict(size=18, color='#FFFFFF', family='Inter, sans-serif'),
                   x=0.5, xanchor='center', y=0.98),
        plot_bgcolor=_BG, paper_bgcolor=_BG,
        xaxis=dict(visible=False, range=[min(x_pos) - pad_x, max(x_pos) + pad_x]),
        yaxis=dict(visible=False, range=[min(y_pos) - pad_y, max(y_pos) + pad_y]),
        showlegend=False,
        margin=dict(l=15, r=15, t=60, b=15),
        font=dict(family='Inter, sans-serif'),
        hoverlabel=dict(bgcolor='#1E293B', font_size=13, bordercolor='#334155')
    )
    return fig.to_image(format=fmt, width=width, height=height)


def render_host_priority(labels, values, title, width, height, fmt='svg', unit='High-Risk CVEs'):
    """Bubble chart for host patch priority. Same layout as render_bubbles with Fortinet Red."""
    return render_bubbles(labels, values, title, width, height, fmt=fmt, unit=unit)
