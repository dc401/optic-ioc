# Optic IOC - Icon Generation Instructions

## Required Icons

The extension requires 4 icon sizes:
- 16x16 pixels (toolbar icon)
- 32x32 pixels (extension management)
- 48x48 pixels (extension management)
- 128x128 pixels (Chrome Web Store, if published)

## Design Guidelines

### Icon Concept
- **Theme**: Magnifying glass with threat intelligence symbol
- **Style**: Modern, minimal, professional
- **Colors**:
  - Primary: Blue (#0088ff) - represents analysis/investigation
  - Secondary: Orange (#ff8800) - represents alerts/threats
  - Background: Transparent

### Icon Design Ideas

**Option 1: Magnifying Glass + Alert**
- Magnifying glass outline in blue
- Small alert/warning triangle in orange in the lens
- Clean, recognizable

**Option 2: Eye + Target**
- Stylized eye (optic = eye)
- Crosshair/target overlay
- Represents "watching for threats"

**Option 3: IOC Symbol**
- Stylized "IOC" letters
- Integrated magnifying glass
- More literal but clear

## Quick Generation Methods

### Method 1: Use an AI Image Generator
1. Use DALL-E, Midjourney, or similar
2. Prompt: "Create a modern, minimal icon for a cybersecurity threat intelligence Chrome extension. Magnifying glass with alert symbol. Blue and orange colors. Transparent background. 512x512 pixels."
3. Downscale to required sizes

### Method 2: Use Figma/Adobe Illustrator
1. Create 128x128 canvas
2. Draw magnifying glass (circle + handle)
3. Add alert triangle or target symbol
4. Export as PNG at all required sizes

### Method 3: Use Free Icon Tools
1. Visit https://icon.kitchen
2. Select "Search" icon as base
3. Customize colors to blue/orange
4. Add overlay symbol
5. Download all sizes

### Method 4: Simple Text-Based (Temporary)
Create simple colored squares with "OI" text:
```
python3 << EOF
from PIL import Image, ImageDraw, ImageFont

def create_icon(size):
    img = Image.new('RGBA', (size, size), (0, 136, 255, 255))
    draw = ImageDraw.Draw(img)

    # Draw border
    draw.rectangle([0, 0, size-1, size-1], outline=(255, 136, 0, 255), width=max(1, size//32))

    # Add text (if size allows)
    if size >= 32:
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", size//2)
        except:
            font = ImageFont.load_default()
        draw.text((size//2, size//2), "OI", fill=(255, 255, 255, 255), anchor="mm", font=font)

    img.save(f'icon-{size}.png')

for size in [16, 32, 48, 128]:
    create_icon(size)
EOF
```

## Current Status

**Icons needed**: 4 files
- icon-16.png ❌
- icon-32.png ❌
- icon-48.png ❌
- icon-128.png ❌

## Temporary Solution

For testing purposes, you can use simple placeholder icons. Run the Python script above in the `icons/` directory to generate basic temporary icons.

Once you have final icons, simply replace the PNG files in this directory.

## Icon Guidelines (Chrome Web Store)

If publishing to Chrome Web Store:
- Format: PNG (with transparency)
- Size: 128x128 pixels required, others optional but recommended
- File size: <1MB each
- Content: Must represent the extension's purpose
- No text smaller than 6pt
- No misleading imagery
