const ld = { "@context": "https://schema.org", "@type": "Organization", name: "Acme" };
export default function Page() {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;
}
