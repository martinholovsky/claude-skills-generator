# UI/UX Advanced Patterns

## Micro-Interactions

```css
/* Button press feedback */
.button {
  transition: transform 0.1s ease, box-shadow 0.1s ease;
}

.button:active {
  transform: scale(0.98);
  box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
}

/* Input focus */
.input {
  transition: border-color 0.2s, box-shadow 0.2s;
}

.input:focus {
  border-color: var(--color-primary-500);
  box-shadow: 0 0 0 3px rgba(0, 188, 212, 0.2);
}
```

## Progressive Loading

```tsx
// Skeleton loading pattern
function DataDisplay({ data, loading }: Props) {
  if (loading) {
    return (
      <div className="skeleton-container">
        <div className="skeleton skeleton-title" />
        <div className="skeleton skeleton-text" />
        <div className="skeleton skeleton-text" />
      </div>
    );
  }

  return <Content data={data} />;
}

// CSS
.skeleton {
  background: linear-gradient(
    90deg,
    rgba(255, 255, 255, 0.1) 25%,
    rgba(255, 255, 255, 0.2) 50%,
    rgba(255, 255, 255, 0.1) 75%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 4px;
}

@keyframes shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
```

## Data Visualization

```tsx
// Circular progress indicator
function CircularProgress({ value, max, size = 100 }: Props) {
  const percentage = (value / max) * 100;
  const circumference = 2 * Math.PI * 40;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      {/* Background circle */}
      <circle
        cx="50" cy="50" r="40"
        fill="none"
        stroke="rgba(255,255,255,0.1)"
        strokeWidth="8"
      />
      {/* Progress circle */}
      <circle
        cx="50" cy="50" r="40"
        fill="none"
        stroke="var(--color-primary-500)"
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={strokeDashoffset}
        transform="rotate(-90 50 50)"
      />
      {/* Value text */}
      <text
        x="50" y="50"
        textAnchor="middle"
        dominantBaseline="middle"
        fill="var(--text-primary)"
        fontSize="20"
      >
        {Math.round(percentage)}%
      </text>
    </svg>
  );
}
```

## Contextual Menus

```tsx
// Right-click context menu
function ContextMenu({ items, position, onClose }: Props) {
  return (
    <div
      className="context-menu glass-card"
      style={{ left: position.x, top: position.y }}
      onBlur={onClose}
    >
      {items.map(item => (
        <button
          key={item.id}
          className="context-menu-item"
          onClick={() => {
            item.action();
            onClose();
          }}
        >
          {item.icon && <span className="icon">{item.icon}</span>}
          <span className="label">{item.label}</span>
          {item.shortcut && <span className="shortcut">{item.shortcut}</span>}
        </button>
      ))}
    </div>
  );
}
```

## Notification Toast System

```tsx
// Toast notification manager
const ToastContext = createContext<ToastManager>(null);

function ToastProvider({ children }: Props) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = (toast: Omit<Toast, 'id'>) => {
    const id = crypto.randomUUID();
    setToasts(prev => [...prev, { ...toast, id }]);

    if (toast.duration !== 0) {
      setTimeout(() => removeToast(id), toast.duration || 5000);
    }
  };

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      <div className="toast-container">
        {toasts.map(toast => (
          <Toast key={toast.id} {...toast} onClose={() => removeToast(toast.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}
```

## Drag and Drop

```tsx
// Sortable list with drag and drop
function SortableList({ items, onReorder }: Props) {
  const [draggedIndex, setDraggedIndex] = useState<number | null>(null);

  const handleDragStart = (index: number) => {
    setDraggedIndex(index);
  };

  const handleDragOver = (e: DragEvent, index: number) => {
    e.preventDefault();
    if (draggedIndex === null || draggedIndex === index) return;

    const newItems = [...items];
    const [removed] = newItems.splice(draggedIndex, 1);
    newItems.splice(index, 0, removed);

    onReorder(newItems);
    setDraggedIndex(index);
  };

  return (
    <ul className="sortable-list">
      {items.map((item, index) => (
        <li
          key={item.id}
          draggable
          onDragStart={() => handleDragStart(index)}
          onDragOver={(e) => handleDragOver(e, index)}
          className={draggedIndex === index ? 'dragging' : ''}
        >
          {item.content}
        </li>
      ))}
    </ul>
  );
}
```
