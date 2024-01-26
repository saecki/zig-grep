#import "@preview/polylux:0.3.1": *
#import "@preview/codelst:2.0.0": sourcecode, code-frame

#let slide-colors = state("slide-colors", (:))
#let slide-short-title = state("slide-short-title", none)
#let slide-short-author = state("slide-short-author", none)
#let slide-short-date = state("slide-short-date", none)
#let slide-progress-bar = state("slide-progress-bar", true)

#let project(
  aspect-ratio: "16-9",
  short-title: none,
  short-author: none,
  short-date: none,
  bg-color: color,
  primary-color: color,
  primary-dimmed-color: color,
  footer-a-color: color,
  footer-b-color: color,
  progress-bar: true,
  body
) = {
  set page(
    paper: "presentation-" + aspect-ratio,
    fill: bg-color,
    margin: 0em,
    header: none,
    footer: none,
  )
  set text(
    fill: rgb("#c0c0b0"),
    size: 25pt,
    font: "JetbrainsMono Nerd Font",
    features: (calt: 0),
    lang: "en",
  )
  show footnote.entry: set text(size: .6em)

  slide-progress-bar.update(progress-bar)
  slide-colors.update((
    bg: bg-color,
    primary: primary-color,
    primary-dimmed: primary-dimmed-color,
    footer-a: footer-a-color,
    footer-b: footer-b-color,
  ))
  slide-short-title.update(short-title)
  slide-short-author.update(short-author)
  slide-short-date.update(short-date)

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
        fill: rgb("#34364a"),
        outset: (y: 3pt),
        inset: (x: 2pt, y: 1pt),
        radius: w-radius,
        text(fill: rgb("#a0c0ff"), word),
      )
    }

    // -- bold --
    // text(weight: "bold", r.text)

    // -- quoted -- 
    // quote(r.text)
  }

  body
}

#let title-slide(
  title: [],
  subtitle: none,
  authors: (),
  institution-name: "University",
  date: none,
  logo: none,
) = {
  let authors = if type(authors) ==  "array" { authors } else { (authors,) }

  let content = locate( loc => {
    let colors = slide-colors.at(loc)

    if logo != none {
      align(right, logo)
    }

    align(center + horizon, {
      block(
        inset: 0em,
        breakable: false,
        {
          text(size: 2em, fill: colors.primary, strong(title))
          if subtitle != none {
            parbreak()
            text(size: 1.2em, fill: colors.primary.desaturate(30%).darken(15%), subtitle)
          }
        }
      )
      set text(size: .8em)
      grid(
        columns: (1fr,) * calc.min(authors.len(), 3),
        column-gutter: 1em,
        row-gutter: 1em,
        ..authors.map(author => text(author))
      )
      v(1em)
      if institution-name != none {
        parbreak()
        text(size: .9em, institution-name)
      }
      if date != none {
        parbreak()
        text(size: .8em, date)
      }
    })
  })

  logic.polylux-slide(content)
}

#let slide(
  title: none,
  header: none,
  footer: none,
  new-section: none,
  body
) = {

  let body = pad(x: 2em, y: .5em, body)
  
  let progress-barline = locate( loc => {
    if slide-progress-bar.at(loc) {
      let cell = block.with( width: 100%, height: 100%, above: 0pt, below: 0pt, breakable: false )
      let colors = slide-colors.at(loc)

      utils.polylux-progress( ratio => {
        grid(
          rows: 2pt, columns: (ratio * 100%, 1fr),
          cell(fill: colors.primary),
          cell(fill: colors.primary-dimmed)
        )
      })
    } else { [] }
  })

  let header-text = {
    if header != none {
      header
    } else if title != none {
      if new-section != none {
        utils.register-section(new-section)
      }
      locate( loc => {
        let colors = slide-colors.at(loc)
        block(inset: (x: .8em), grid(
          columns: (60%, 40%),
          align(top + left, heading(level: 2, text(fill: colors.primary, title))),
          align(top + right, text(fill: colors.primary.desaturate(50%).darken(20%), utils.current-section))
        ))
      })
    } else { [] }
  }

  let header = {
    set align(top)
    grid(rows: (auto, auto), row-gutter: 3mm, progress-barline, header-text)
  }

  set page(
    margin: ( top: 2em, bottom: 1em, x: 0em ),
    header: header,
    footer-descent: 0em,
    header-ascent: .6em,
  )

  logic.polylux-slide[
    #align(horizon, body)
  ]
}

#let focus-slide(
  background-color: color,
  background-img: none,
  new-section: none,
  body,
) = {
  let background-color = if background-img == none and background-color ==  none {
    rgb("#0C6291")
  } else {
    background-color
  }

  set page(fill: background-color, margin: 1em) if background-color != none
  set page(
    background: {
      set image(fit: "stretch", width: 100%, height: 100%)
      background-img
    },
    margin: 1em,
  ) if background-img != none

  set text(size: 2em)

  logic.polylux-slide(align(horizon, body))

  if new-section != none {
    utils.register-section(new-section)
  }
}

#let code-space() = {
  v(0fr)
  v(0.41em)
}

#let dimmed-code(code) = {
  show raw.where(block: true): r => {
    text(size: 16pt, font: "JetbrainsMono Nerd Font", fill: rgb("#484848"), r.text)
  }

  code-space()
  code
}

#let code(code) = {
  set raw(theme: "Catppuccin-macchiato.tmTheme")
  show raw.where(block: true): r => {
    text(size: 16pt, font: "JetbrainsMono Nerd Font", fill: rgb("#f8eddd"), r)
  }

  code-space()
  code
}

#let walk-through-slides(
  title: str,
  code-parts: ([]),
  highlighted-parts: (),
) = {
  for hl in highlighted-parts {
    slide(title: title)[
      #for (idx, part) in code-parts.enumerate() {
        if hl.contains(idx) {
          code(part)
        } else {
          dimmed-code(part)
        }
      }
    ]
  }
}
