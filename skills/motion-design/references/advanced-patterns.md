# Motion Design Advanced Patterns

## Complex Choreography

```typescript
// Orchestrated multi-element animation
import { motion, useAnimation } from "framer-motion";

function DashboardEntrance() {
  const controls = useAnimation();

  useEffect(() => {
    async function sequence() {
      // Header first
      await controls.start("header");
      // Then sidebar
      await controls.start("sidebar");
      // Finally main content
      await controls.start("main");
    }
    sequence();
  }, []);

  return (
    <div>
      <motion.header
        initial={{ y: -50, opacity: 0 }}
        animate={controls}
        variants={{
          header: { y: 0, opacity: 1, transition: { duration: 0.3 } }
        }}
      />
      <motion.aside
        initial={{ x: -50, opacity: 0 }}
        animate={controls}
        variants={{
          sidebar: { x: 0, opacity: 1, transition: { duration: 0.3 } }
        }}
      />
      <motion.main
        initial={{ opacity: 0, scale: 0.95 }}
        animate={controls}
        variants={{
          main: { opacity: 1, scale: 1, transition: { duration: 0.4 } }
        }}
      />
    </div>
  );
}
```

## Gesture-Based Interactions

```typescript
// Swipe to dismiss
function SwipeableCard({ onDismiss }: Props) {
  return (
    <motion.div
      drag="x"
      dragConstraints={{ left: 0, right: 0 }}
      dragElastic={0.1}
      onDragEnd={(_, info) => {
        if (Math.abs(info.offset.x) > 100) {
          onDismiss();
        }
      }}
      whileDrag={{ scale: 0.98 }}
    >
      {/* Card content */}
    </motion.div>
  );
}
```

## Physics-Based Animations

```typescript
// Momentum scrolling with decay
import { motion, useMotionValue, useTransform } from "framer-motion";

function MomentumScroll({ children }: Props) {
  const y = useMotionValue(0);
  const opacity = useTransform(y, [-100, 0, 100], [0.5, 1, 0.5]);

  return (
    <motion.div
      style={{ y, opacity }}
      drag="y"
      dragElastic={0.2}
      dragMomentum={true}
      dragTransition={{ bounceStiffness: 300, bounceDamping: 20 }}
    >
      {children}
    </motion.div>
  );
}
```

## Morphing Shapes

```css
/* SVG path morphing */
@keyframes morphShape {
  0% {
    d: path("M10,10 L90,10 L90,90 L10,90 Z");
  }
  50% {
    d: path("M50,10 L90,50 L50,90 L10,50 Z");
  }
  100% {
    d: path("M10,10 L90,10 L90,90 L10,90 Z");
  }
}

.morph-path {
  animation: morphShape 3s ease-in-out infinite;
}
```

## Scroll-Linked Animations

```typescript
// Parallax and scroll-triggered animations
import { motion, useScroll, useTransform } from "framer-motion";

function ParallaxSection() {
  const { scrollYProgress } = useScroll();

  const y = useTransform(scrollYProgress, [0, 1], ["0%", "50%"]);
  const opacity = useTransform(scrollYProgress, [0, 0.5, 1], [1, 0.5, 0]);

  return (
    <motion.div style={{ y, opacity }}>
      {/* Content */}
    </motion.div>
  );
}
```

## Loading Choreography

```typescript
// Multi-stage loading animation
function LoadingSequence() {
  return (
    <div className="loading-container">
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          className="loading-dot"
          animate={{
            y: [-8, 0, -8],
            opacity: [0.5, 1, 0.5]
          }}
          transition={{
            duration: 0.8,
            repeat: Infinity,
            delay: i * 0.15,
            ease: "easeInOut"
          }}
        />
      ))}
    </div>
  );
}
```

## Transition Variants

```typescript
// Reusable animation variants
const fadeSlideVariants = {
  initial: {
    opacity: 0,
    y: 20
  },
  animate: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.3,
      ease: [0, 0, 0.2, 1]
    }
  },
  exit: {
    opacity: 0,
    y: -10,
    transition: {
      duration: 0.2,
      ease: [0.4, 0, 1, 1]
    }
  }
};

// Usage with AnimatePresence
<AnimatePresence>
  {isVisible && (
    <motion.div
      variants={fadeSlideVariants}
      initial="initial"
      animate="animate"
      exit="exit"
    >
      {content}
    </motion.div>
  )}
</AnimatePresence>
```
