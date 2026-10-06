import { useEffect, useState } from "react";
import Icon from "./Icon";
import { usePrefersReducedMotion } from "../settings/SettingsContext";

interface Props {
  message: string;
  onGone: () => void;
}

export default function Toast({ message, onGone }: Props) {
  const reduced = usePrefersReducedMotion();
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    setLeaving(false);
    const id = window.setTimeout(() => setLeaving(true), 2800);
    return () => window.clearTimeout(id);
  }, [message]);

  useEffect(() => {
    if (!leaving) return;
    const id = window.setTimeout(onGone, reduced ? 0 : 220);
    return () => window.clearTimeout(id);
  }, [leaving, reduced, onGone]);

  return (
    <div className={`toast${leaving ? " out" : ""}`} role="status">
      <Icon name="check" size={16} />
      {message}
    </div>
  );
}
