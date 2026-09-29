import {
  Activity,
  ArrowRight,
  BookOpen,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock,
  Code,
  Download,
  ExternalLink,
  Eye,
  FileCheck,
  Flag,
  Globe,
  Info,
  Layers,
  LayoutDashboard,
  LayoutGrid,
  LifeBuoy,
  Lightbulb,
  Lock,
  Menu,
  Monitor,
  Moon,
  RefreshCw,
  ScanSearch,
  Send,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Target,
  Trash2,
  TriangleAlert,
  User,
  X,
  type LucideIcon,
} from "lucide-react";

const ICONS = {
  dashboard: LayoutDashboard,
  target: Target,
  shieldCheck: ShieldCheck,
  fileCheck: FileCheck,
  download: Download,
  refresh: RefreshCw,
  alert: TriangleAlert,
  activity: Activity,
  info: Info,
  chevronDown: ChevronDown,
  chevronRight: ChevronRight,
  arrowRight: ArrowRight,
  sun: Sun,
  moon: Moon,
  menu: Menu,
  server: Server,
  book: BookOpen,
  lightbulb: Lightbulb,
  eye: Eye,
  x: X,
  check: Check,
  clock: Clock,
  layers: Layers,
  grid: LayoutGrid,
  help: CircleHelp,
  sliders: SlidersHorizontal,
  user: User,
  lifeBuoy: LifeBuoy,
  send: Send,
  external: ExternalLink,
  flag: Flag,
  globe: Globe,
  lock: Lock,
  code: Code,
  monitor: Monitor,
  trash: Trash2,
} as const satisfies Record<string, LucideIcon>;

export type IconName = keyof typeof ICONS;

interface Props {
  name: IconName;
  size?: number;
  className?: string;
}

export default function Icon({ name, size = 18, className = "" }: Props) {
  const Glyph = ICONS[name];
  return (
    <Glyph
      className={`ic ${className}`.trim()}
      size={size}
      strokeWidth={1.75}
      color="currentColor"
      aria-hidden="true"
    />
  );
}

/** Same mark in the splash and the sidebar: Lucide ScanSearch on the accent tile. */
export function Logo({ size = 30, className = "" }: { size?: number; className?: string }) {
  const radius = Math.max(6, Math.round(size * 0.28));
  return (
    <span
      className={`logo ${className}`.trim()}
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        borderRadius: radius,
        background: "var(--accent)",
        color: "var(--accent-ink)",
        display: "grid",
        placeItems: "center",
      }}
    >
      <ScanSearch size={Math.round(size * 0.62)} strokeWidth={1.75} color="currentColor" aria-hidden="true" />
    </span>
  );
}
