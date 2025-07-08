import os
from fpdf import FPDF
from PIL import Image, ImageDraw

# Générer 3 fichiers textes
for i in range(1, 4):
    with open(f"fichier_{i}.txt", "w", encoding="utf-8") as f:
        f.write(f"Ceci est le fichier texte numéro {i}.\n")

# Générer un fichier PDF
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdf.cell(200, 10, txt="Ceci est un fichier PDF généré par Python.", ln=True, align='C')
pdf.output("fichier.pdf")

# Générer un fichier PNG
img = Image.new('RGB', (200, 100), color=(73, 109, 137))
d = ImageDraw.Draw(img)
d.text((10, 40), "Image PNG générée", fill=(255, 255, 0))
img.save("image.png")

# Créer un sous-dossier et y mettre 3 fichiers
os.makedirs("sous_dossier", exist_ok=True)
for i in range(1, 4):
    with open(os.path.join("sous_dossier", f"sous_fichier_{i}.txt"), "w", encoding="utf-8") as f:
        f.write(f"Ceci est le sous-fichier numéro {i}.\n")