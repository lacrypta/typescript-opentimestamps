// typescript-opentimestamps: An OpenTimestamps client written in TypeScript.
// Copyright (C) 2024  La Crypta
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

'use strict';

import type { Application, Context, Comment } from 'typedoc';

import { ParameterType, CommentTag, Converter } from 'typedoc';

function lowercaseFirst(str: string): string {
  return str.charAt(0).toLowerCase() + str.slice(1);
}

export function load(application: Readonly<Application>) {
  application.options.addDeclaration({
    type: ParameterType.Array,
    name: 'conditions',
    help: 'The list of true conditions for this run.',
    defaultValue: [],
    validate: (value: unknown): void => {
      if (!Array.isArray(value) || value.some((val: unknown): boolean => 'string' !== typeof val)) {
        throw Error('Expected array of strings');
      }
    },
  });

  let config: string[] = [];
  application.converter.on(Converter.EVENT_BEGIN, (_context: Context): void => {
    config = application.options.getValue('conditions') as unknown as string[];
    application.logger.info(`Conditions: [${config.join(', ')}]`);
  });

  application.converter.on(Converter.EVENT_RESOLVE_BEGIN, (context: Context): void => {
    for (const key in context.project.reflections) {
      const comment: Comment | undefined = context.project.reflections[key]?.comment;
      if (undefined !== comment) {
        const newBlockTags: CommentTag[] = [];
        for (const tag of comment.blockTags) {
          const matches: RegExpExecArray | null = /^@when(?<conditionName>[A-Z][a-z0-9]*)(?<tagName>[A-Z].*)$/.exec(
            tag.tag,
          );
          if (null !== matches) {
            const conditionName: string = lowercaseFirst(matches.groups!.conditionName!);
            const tagName: string = lowercaseFirst(matches.groups!.tagName!);
            if (-1 !== config.indexOf(conditionName)) {
              const newTag = new CommentTag(`@${tagName}`, tag.content);
              if (undefined !== tag.name) {
                newTag.name = tag.name;
              }
              newBlockTags.push(newTag);
            }
          } else {
            newBlockTags.push(tag);
          }
        }
        comment.blockTags = newBlockTags;
      }
    }
  });
}
