interface Props {
  title: string;
  lead?: string;
  id?: string;
}

/** Page header shared by the stand-alone pages (same markup as the dashboard). */
export default function PageHead({ title, lead, id }: Props) {
  return (
    <div className="page-head">
      <div className="ph-text">
        <h1 id={id} tabIndex={-1}>
          {title}
        </h1>
        {lead && <p className="lead">{lead}</p>}
      </div>
    </div>
  );
}
