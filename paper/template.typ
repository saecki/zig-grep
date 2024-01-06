#import "@preview/codelst:1.0.0": sourcecode, code-frame

#let project(title: str, author: str, body) = {
    // Set the document's basic properties.
    set document(author: author, title: title)
    set page(
        paper: "a4",
        margin: (x: 2.5cm, y: 2.5cm),
        numbering: "1",
        number-align: center,
    )
    set text(
        font: "Linux Libertine",
        lang: "en",
    )
    set heading(numbering: "1.")

    // superscript citations
    // show cite.where(supplement: none, form: "normal"): c => {
    //     super(cite(form: "prose", c.key))
    // }

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

#let output(content) = {
    sourcecode(
        numbering: none,
        frame: code-frame.with(
            fill: luma(240),
            stroke: none,
            inset: (left: 1.8em, right: .45em, y: .65em)
        ),
        content,
    )
}
