import re
import matplotlib.pyplot as plt

xs = []
ys = []
in_flag = False

with open(r"3D.gcode", "r") as f:
    for line in f:
        line = line.strip()
        if ";MESH:flag.stl" in line:
            in_flag = True
            continue
        if ";MESH:" in line and "flag.stl" not in line:
            in_flag = False
            continue
        if in_flag and line.startswith("G1"):
            xm = re.search(r'X([\d.]+)', line)
            ym = re.search(r'Y([\d.]+)', line)
            if xm and ym:
                xs.append(float(xm.group(1)))
                ys.append(float(ym.group(1)))

plt.figure(figsize=(20, 6))
plt.scatter(xs, ys, s=0.1, c='black')
plt.axis('equal')
plt.title('flag.stl top-down view')
plt.savefig('flag_plot.png', dpi=200)
plt.show()
print(f"Plotted {len(xs)} points")
