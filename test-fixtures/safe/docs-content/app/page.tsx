// A normal marketing page that embeds JSON-LD structured data — the standard,
// safe React pattern. The injected value is JSON.stringify() of a static object,
// never user input, so it must NOT be flagged as an unsanitized-HTML XSS sink.

const faqJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: [
    { '@type': 'Question', name: 'Is the scan free?', acceptedAnswer: { '@type': 'Answer', text: 'Yes.' } },
  ],
};

export default function Page() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }}
      />
      <h1>Veilguard</h1>
    </>
  );
}
