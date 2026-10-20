export default function Page({ searchParams }: any) {
  return <div dangerouslySetInnerHTML={{ __html: searchParams.q }} />;
}
