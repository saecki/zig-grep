// The project function defines how your document looks.
// It takes your content and some metadata and formats it.
// Go ahead and customize it to your liking!
#let project(title: "", author: "", logo: none, logo_tag: none, body) = {
  // Set the document's basic properties.
  set document(author: author, title: title)
  set page(
      paper: "a4",
      margin: (x: 2.5cm, y: 1.5cm),
      numbering: "1",
      number-align: center,
  )
  set text(
      font: "Linux Libertine",
      lang: "en",
  )
  set heading(numbering: "1.")

  v(2.4fr)
  if logo != none {
    align(center, image(logo, width: 80%))
    if logo_tag != none {
        align(center, cite(logo_tag))
    }
  }
  v(2.0fr)

  // Title
  align(center, text(1.8em, weight: 500, title))
  v(0.6fr)

  // Author information.
  align(center, strong(author))
  v(0.3fr)

  align(center, datetime.today().display())

  v(2.4fr)
  pagebreak()

  // Outline.
  outline()
  pagebreak()


  // Main body.
  set par(justify: true)

  // Prettier raw text
  show raw.where(lang: none, block: false): r => {
    // -- blue highlighted --
    let words = r.text.split(" ")
    for (idx, word) in words.enumerate() {
      let w-radius = if words.len() == 1 {
        3pt
      } else if idx == 0 {
        (left: 3pt)
      } else if idx == words.len() - 1 {
        (right: 3pt)
      } else {
        0pt
      }
      
      box(
        fill: rgb("#f4f6fa"),
        outset: (y: 3pt),
        inset: (x: 2pt),
        radius: w-radius,
        text(fill: rgb("#4050d0"), word),
      )
    }

    // -- bold --
    // text(weight: "bold", r.text)

    // -- quoted -- 
    // quote(r.text)
  }

  body
}
