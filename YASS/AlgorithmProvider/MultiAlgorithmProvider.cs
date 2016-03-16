// YASS - Yet another Shadowsocks
// Copyright (C) 2016 dantmnf
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace YASS.AlgorithmProvider
{
    public class MultiAlgorithmProvider : IAlgorithmProvider
    {
        private readonly List<IAlgorithmProvider> _providers = new List<IAlgorithmProvider>(); 
        private IAlgorithmProvider GetProvider(string name)
        {
            foreach (var provider in _providers)
            {
                var result = provider.GetSupportedCiphers();
                if (result.Contains(name))
                {
                    return provider;
                }
            }
            throw new NotSupportedException($"cipher {name} not found.");
        }

        public void AddProvider(IAlgorithmProvider provider)
        {
            _providers.Add(provider);
        }

        public void AddProviders(IEnumerable<IAlgorithmProvider> providers)
        {
            foreach (var provider in providers)
            {
                AddProvider(provider);
            }
        }

        public string[] GetSupportedCiphers()
        {
            return (from provider in _providers
                    from name in provider.GetSupportedCiphers()
                    select name).Distinct().ToArray();
        }

        public SymmetricAlgorithm GetAlgorithm(string name)
        {
            return GetProvider(name).GetAlgorithm(name);
        }

        public bool IsAvailable() => GetSupportedCiphers().Length != 0;

        public static MultiAlgorithmProvider FindAndCreate()
        {
            var providerInterfaceType = typeof(IAlgorithmProvider);
            var providerTypes = from assembly in AppDomain.CurrentDomain.GetAssemblies()
                                from type in assembly.GetExportedTypes()
                                where type.IsClass && type.IsPublic
                                from attr in type.GetCustomAttributes()
                                where providerInterfaceType.IsAssignableFrom(type) && attr is AlgorithmProviderAttribute
                                let providerattr = attr as AlgorithmProviderAttribute
                                orderby providerattr.Metric ascending
                                select type;
            var multiProvider = new MultiAlgorithmProvider();
            foreach (var type in providerTypes)
            {
                var provider = type.GetConstructor(new Type[] { })?.Invoke(new object[] { }) as IAlgorithmProvider;
                if (provider != null && provider.IsAvailable()) multiProvider.AddProvider(provider);
            }
            return multiProvider;
        }
    }
}