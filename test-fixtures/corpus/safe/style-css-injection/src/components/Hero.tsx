const HERO_CSS = `.hero{display:grid;gap:1rem}`;
const localCss = '.a{color:red}';
export function Hero() {
  return (<>
    <style dangerouslySetInnerHTML={{ __html: HERO_CSS }} />
    <style dangerouslySetInnerHTML={{ __html: localCss }} />
  </>);
}
