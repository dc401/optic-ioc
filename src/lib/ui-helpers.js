//Optic IOC - UI Helper Utilities
//Reusable panel/alert creation to eliminate duplication

class UIPanelBuilder {
  //Create a fixed-position panel with standard styling
  static createPanel(config) {
    const {
      id,
      position = 'right',
      offset = '20px',
      top = '80px',
      width = '400px',
      maxHeight = '85vh',
      background = 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
      border = '3px solid #4a9eff',
      zIndex = OPTIC_CONSTANTS.Z_INDEX?.PANEL || 9999999,
      color = '#ffffff',
      shadow = '0 8px 32px rgba(0,0,0,0.7)',
      animation = null,
      extraStyles = []
    } = config;

    //Remove existing panel if present
    const existing = document.getElementById(id);
    if (existing) existing.remove();

    const panel = document.createElement('div');
    panel.id = id;

    const styles = [
      'position: fixed',
      `top: ${top}`,
      `${position}: ${offset}`,
      `width: ${width}`,
      `max-height: ${maxHeight}`,
      `background: ${background}`,
      `border: ${border}`,
      'border-radius: 12px',
      `z-index: ${zIndex}`,
      'font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      'font-size: 13px',
      `color: ${color}`,
      `box-shadow: ${shadow}`,
      'overflow: hidden',
      ...extraStyles
    ];

    panel.style.cssText = styles.join('; ') + ';';

    //Add animation if provided
    if (animation) {
      const animId = `${id}-animation`;
      if (!document.getElementById(animId)) {
        const style = document.createElement('style');
        style.id = animId;
        style.textContent = animation;
        document.head.appendChild(style);
      }
    }

    return panel;
  }

  //Create a standard close button
  static createCloseButton(onClick) {
    const btn = document.createElement('button');
    btn.textContent = '×';
    btn.style.cssText = `
      background: rgba(255,255,255,0.2);
      border: none;
      color: white;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 20px;
      font-weight: 700;
      transition: background 0.2s;
      width: 24px;
      height: 24px;
    `;
    btn.onmouseover = () => btn.style.background = 'rgba(255,255,255,0.3)';
    btn.onmouseout = () => btn.style.background = 'rgba(255,255,255,0.2)';
    btn.onclick = onClick;
    return btn;
  }

  //Create a standard header with title and close button
  static createHeader(title, subtitle = null, closeCallback = null) {
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      background: rgba(74, 158, 255, 0.15);
      border-bottom: 1px solid rgba(74, 158, 255, 0.3);
    `;

    const headerText = document.createElement('div');
    headerText.style.cssText = 'flex: 1;';

    const titleEl = document.createElement('h3');
    titleEl.style.cssText = 'margin: 0; font-size: 15px; font-weight: 600;';
    titleEl.textContent = title;
    headerText.appendChild(titleEl);

    if (subtitle) {
      const subtitleEl = document.createElement('div');
      subtitleEl.style.cssText = 'font-size: 11px; color: #aaa; margin-top: 2px;';
      subtitleEl.textContent = subtitle;
      headerText.appendChild(subtitleEl);
    }

    header.appendChild(headerText);

    if (closeCallback) {
      const controls = document.createElement('div');
      controls.style.cssText = 'display: flex; gap: 8px;';
      controls.appendChild(this.createCloseButton(closeCallback));
      header.appendChild(controls);
    }

    return header;
  }

  //Create a content container
  static createContent(maxHeight = 'calc(70vh - 60px)') {
    const content = document.createElement('div');
    content.style.cssText = `padding: 16px; max-height: ${maxHeight}; overflow-y: auto;`;
    return content;
  }

  //Auto-dismiss a panel after timeout
  static autoDismiss(element, timeout = 15000, fadeOut = true, onDismiss = null) {
    const timer = setTimeout(() => {
      if (fadeOut) {
        element.style.transition = 'opacity 0.5s, transform 0.5s';
        element.style.opacity = '0';
        element.style.transform = 'translateX(400px)';
        setTimeout(() => {
          if (element.parentNode) element.remove();
          if (onDismiss) onDismiss();
        }, 500);
      } else {
        if (element.parentNode) element.remove();
        if (onDismiss) onDismiss();
      }
    }, timeout);

    return timer; //Return timer ID so caller can cancel if needed
  }

  //Get threat-level colors
  static getThreatColors(level) {
    const colors = {
      critical: { bg: '#2a0a0a', border: '#ff0000', text: '#ff4444', gradient: 'linear-gradient(135deg, #ff4444 0%, #cc0000 100%)' },
      high: { bg: '#2a1500', border: '#ff8800', text: '#ff8844', gradient: 'linear-gradient(135deg, #ff8800 0%, #cc6600 100%)' },
      medium: { bg: '#2a2200', border: '#ffaa00', text: '#ffaa44', gradient: 'linear-gradient(135deg, #ffaa00 0%, #cc8800 100%)' },
      low: { bg: '#0a1a0a', border: '#00cc44', text: '#00cc00', gradient: 'linear-gradient(135deg, #00cc44 0%, #009933 100%)' },
      none: { bg: '#0a1a0a', border: '#00cc44', text: '#00cc00', gradient: 'linear-gradient(135deg, #00cc44 0%, #009933 100%)' },
      unknown: { bg: '#1a1a1a', border: '#888888', text: '#888888', gradient: 'linear-gradient(135deg, #888888 0%, #666666 100%)' }
    };
    return colors[level] || colors.unknown;
  }
}

//Export for modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UIPanelBuilder };
}

//Make globally available
if (typeof self !== 'undefined') {
  self.UIPanelBuilder = UIPanelBuilder;
}
