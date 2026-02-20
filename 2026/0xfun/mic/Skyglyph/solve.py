import numpy as np
import csv
from scipy.optimize import least_squares
import matplotlib.pyplot as plt

# Read CSV
rows = []
guides = []
with open('tracker_dump.csv', 'r') as f:
    reader = csv.DictReader(f)
    for r in reader:
        x = float(r['x_px'])
        y = float(r['y_px'])
        flux = float(r['flux'])
        name = r['name'].strip() if r['name'] else ''
        ra_h = float(r['ra_h']) if r['ra_h'] else None
        dec_deg = float(r['dec_deg']) if r['dec_deg'] else None
        rows.append((x, y, flux, name, ra_h, dec_deg))
        if name:
            guides.append((x, y, flux, name, ra_h, dec_deg))

print(f"Total detections: {len(rows)}, Guide stars: {len(guides)}")
for g in guides:
    print(f"  {g[3]}: px=({g[0]:.1f}, {g[1]:.1f}), RA={g[4]:.6f}h, Dec={g[5]:.6f}°")

# Convert RA/Dec to radians, handle wrapping around 0h/24h
# RA center ~ 0h (23.9h wraps to ~0h)
# Use Vega as reference point
ra0_h = 23.92  # Vega
dec0_deg = 22.0  # Vega

def ra_dec_to_tangent(ra_h, dec_deg, ra0_h, dec0_deg):
    """Gnomonic (tangent-plane) projection"""
    ra = ra_h * 15 * np.pi / 180  # hours -> degrees -> radians
    dec = dec_deg * np.pi / 180
    ra0 = ra0_h * 15 * np.pi / 180
    dec0 = dec0_deg * np.pi / 180

    cos_c = (np.sin(dec0)*np.sin(dec) +
             np.cos(dec0)*np.cos(dec)*np.cos(ra - ra0))

    u = np.cos(dec) * np.sin(ra - ra0) / cos_c
    v = (np.cos(dec0)*np.sin(dec) - np.sin(dec0)*np.cos(dec)*np.cos(ra - ra0)) / cos_c
    return u, v

# Compute tangent-plane coords for guide stars
guide_uv = []
guide_xy = []
for g in guides:
    u, v = ra_dec_to_tangent(g[4], g[5], ra0_h, dec0_deg)
    guide_uv.append((u, v))
    guide_xy.append((g[0], g[1]))
    print(f"  {g[3]}: u={u:.6f}, v={v:.6f}")

guide_uv = np.array(guide_uv)
guide_xy = np.array(guide_xy)

# Camera model: pixel (x,y) -> tangent-plane (u,v)
# 1. Shift to optical center: x' = x - cx, y' = y - cy
# 2. Apply radial distortion: r = sqrt(x'^2 + y'^2),
#    x'' = x'*(1 + k1*r^2 + k2*r^4), y'' = y'*(1 + k1*r^2 + k2*r^4)
# 3. Affine transform: u = a*x'' + b*y'' + e, v = c*x'' + d*y'' + f
# Parameters: cx, cy, k1, k2, a, b, c, d

# Actually let's parameterize as:
# params = [cx, cy, k1, a, b, c, d]
# where (cx,cy) is optical center, k1 is radial distortion coefficient
# and [[a,b],[c,d]] is the affine matrix

def pixel_to_tangent(x, y, params):
    cx, cy, k1, a, b, c, d = params
    dx = x - cx
    dy = y - cy
    r2 = dx**2 + dy**2
    # Normalize r2 by image scale to keep k1 reasonable
    scale = 512**2
    r2n = r2 / scale
    factor = 1 + k1 * r2n
    dx2 = dx * factor
    dy2 = dy * factor
    u = a * dx2 + b * dy2
    v = c * dx2 + d * dy2
    return u, v

def residuals(params):
    res = []
    for i in range(len(guide_xy)):
        u_pred, v_pred = pixel_to_tangent(guide_xy[i, 0], guide_xy[i, 1], params)
        res.append(u_pred - guide_uv[i, 0])
        res.append(v_pred - guide_uv[i, 1])
    return res

# Initial guess: center at (512, 512), no distortion, simple scale
# Estimate scale from spread of pixel coords vs tangent coords
u_range = guide_uv[:, 0].max() - guide_uv[:, 0].min()
v_range = guide_uv[:, 1].max() - guide_uv[:, 1].min()
x_range = guide_xy[:, 0].max() - guide_xy[:, 0].min()
y_range = guide_xy[:, 1].max() - guide_xy[:, 1].min()
scale_est = max(u_range / x_range, v_range / y_range)
print(f"\nScale estimate: {scale_est:.8f} rad/px")

p0 = [512, 512, 0.0, scale_est, 0, 0, scale_est]

result = least_squares(residuals, p0, method='lm')
print(f"\nFit result: cost={result.cost:.2e}, success={result.success}")
print(f"Parameters: {result.x}")

params = result.x
cx, cy, k1, a, b, c, d = params
print(f"  Optical center: ({cx:.1f}, {cy:.1f})")
print(f"  Distortion k1: {k1:.6f}")
print(f"  Matrix: [[{a:.8f}, {b:.8f}], [{c:.8f}, {d:.8f}]]")

# Check residuals for guide stars
print("\nGuide star residuals:")
for i, g in enumerate(guides):
    u_pred, v_pred = pixel_to_tangent(guide_xy[i, 0], guide_xy[i, 1], params)
    du = u_pred - guide_uv[i, 0]
    dv = v_pred - guide_uv[i, 1]
    err = np.sqrt(du**2 + dv**2) * 180 / np.pi * 3600  # arcsec
    print(f"  {g[3]}: err = {err:.2f} arcsec")

# Now transform ALL detections to tangent-plane
all_u = []
all_v = []
all_flux = []
for r in rows:
    u, v = pixel_to_tangent(r[0], r[1], params)
    all_u.append(u)
    all_v.append(v)
    all_flux.append(r[2])

all_u = np.array(all_u)
all_v = np.array(all_v)
all_flux = np.array(all_flux)

# Per README: Use Deneb to define +X, Altair to choose sign of +Y
# Find Deneb and Altair in tangent plane
deneb_idx = next(i for i, g in enumerate(guides) if g[3] == 'Deneb')
altair_idx = next(i for i, g in enumerate(guides) if g[3] == 'Altair')

deneb_u, deneb_v = pixel_to_tangent(guides[deneb_idx][0], guides[deneb_idx][1], params)
altair_u, altair_v = pixel_to_tangent(guides[altair_idx][0], guides[altair_idx][1], params)

# Deneb defines +X direction
angle_deneb = np.arctan2(deneb_v, deneb_u)
print(f"\nDeneb angle: {np.degrees(angle_deneb):.2f}°")
print(f"Deneb (u,v): ({deneb_u:.6f}, {deneb_v:.6f})")
print(f"Altair (u,v): ({altair_u:.6f}, {altair_v:.6f})")

# Rotate so Deneb is along +X
cos_a = np.cos(-angle_deneb)
sin_a = np.sin(-angle_deneb)
rot_u = all_u * cos_a - all_v * sin_a
rot_v = all_u * sin_a + all_v * cos_a

# Check Altair's y after rotation
altair_rot_v = altair_u * sin_a + altair_v * cos_a
print(f"Altair rotated v: {altair_rot_v:.6f}")
if altair_rot_v < 0:
    rot_v = -rot_v
    print("Flipped Y axis")

# Plot
fig, axes = plt.subplots(1, 2, figsize=(20, 10))

# Plot 1: Raw pixel coordinates
axes[0].scatter([r[0] for r in rows], [r[1] for r in rows], s=1, alpha=0.3)
axes[0].set_title('Raw pixel coordinates')
axes[0].set_aspect('equal')

# Plot 2: Calibrated tangent-plane
axes[1].scatter(rot_u, rot_v, s=1, alpha=0.3, c='black')
axes[1].set_title('Calibrated tangent-plane (Deneb=+X)')
axes[1].set_aspect('equal')
axes[1].invert_xaxis()  # RA increases right conventionally

plt.tight_layout()
plt.savefig('calibrated.png', dpi=150)
plt.close()
print("Saved calibrated.png")

# Also try with flux filtering
fig2, ax2 = plt.subplots(figsize=(16, 10))
flux_threshold = np.percentile(all_flux, 50)
mask = all_flux >= flux_threshold
ax2.scatter(rot_u[mask], rot_v[mask], s=2, alpha=0.5, c='black')
ax2.set_title(f'Calibrated (flux >= {flux_threshold:.1f})')
ax2.set_aspect('equal')
plt.tight_layout()
plt.savefig('calibrated_filtered.png', dpi=150)
plt.close()
print("Saved calibrated_filtered.png")
